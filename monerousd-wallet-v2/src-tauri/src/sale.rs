// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A PROTECTED SALE BETWEEN TWO PEOPLE, WITH NOTHING TO PASTE (user 2026-11-10: "i dont even know how to use the
//! merchant feature and i built it … the ease of use bar is someone whos not tech savvy").
//!
//! THE SELLER types what it is and the price, and gets ONE link to send. THE BUYER opens the link and confirms one
//! sentence. From there the two wallets talk to each other over the chain's own private letters (sealed to the
//! recipient, signed by the sender, relayed by nodes that learn nothing): the request, the acceptance, the lock and
//! the notice. At handover the buyer confirms receipt and the code travels the same way; the seller's wallet takes
//! the money by itself. Nobody copies a code unless a wallet was closed in between, and then the code is shown.
//!
//! THE LINK. `monerousd:sale?s=<@name or address>&a=<atomic price>&h=<hours>&p=<period>&n=<nonce>&k=<mark>&t=<title>`
//! and, when the seller set them, `&d=<deposit>` and `&b=<delivery bond>`. The mark is this wallet's keyed hash over
//! every term, so the seller's wallet answers only for an offer it made, on the terms it set, and keeps no list of
//! offers to do so.
//!
//! THE TERMS A SELLER MAY ADD (spec §3.5, §16.1, §18), each one sentence to the buyer before the tap:
//!   * A DEPOSIT: paid to the seller at the order and final (made-to-order work). The rest of the price is in escrow.
//!   * A DELIVERY BOND: the seller locks its own money beside the buyer's. The buyer's receipt code returns it; with no
//!     delivery by the deadline the buyer takes its payment back AND the bond. A seller that cancels gives the bond up:
//!     a buyer with an altered wallet could keep it anyway, so the wallet promises the seller nothing it cannot enforce.
//!   * PICKUP AT A RELAY (the buyer's choice): a third wallet that receives the parcel locks a custody bond worth the
//!     price when it signs for it. The buyer's receipt code returns the bond; a relay that keeps a parcel loses the
//!     bond to the seller at the deadline, so it gains nothing.
//!
//!   * A DOWNLOAD (spec §3.3; `digital`): the seller picks a file. Its sealed bytes and one proof are stored on the Veil,
//!     and the link names the content, the delivery lock and where the sealed bytes are (`x`, `l`, `c`, `v`). The
//!     buyer's wallet reads the sealed bytes, checks the proof, and only then asks the buyer. The seller's wallet is
//!     paid by a spend that hands the buyer the key, so nobody confirms anything: the file opens, or the payment
//!     returns at the deadline.
//!
//!   * THE DOORSTEP (spec §16; `notice`): the seller's wallet tells the buyer's the parcel's tracking number. That is
//!     only an OFFER: a seller chooses the number, so a wallet that pinned it by itself could be shown the delivery of
//!     some other parcel and release the payment for it. The BUYER accepts the number (after reading, in plain words,
//!     that the carrier's own page must show it going to the buyer's address), and only then is it PINNED (one number
//!     an order, with the time). When the carrier's signed delivery notice arrives the seller's wallet proves it and
//!     the buyer's wallet checks the proof and confirms receipt by itself. Only for a carrier whose mail key this
//!     build holds; with none, a tracking number is not even offered, and a sale is confirmed by the buyer as before.
//!
//! NO REPUTATION, BY DECISION (user 2026-11-10: "is it monero ethos? … monerousd is a monero ethos private project").
//! A public standing a seller burns money into was built and removed the same day: it leaves a linkable trail under a
//! name and destroys money for a signal. What protects a buyer here is private and per sale: escrow, and the seller's
//! own bond.
//!
//! WHAT EACH SIDE CAN DO TO THE OTHER: nothing beyond the sale. The buyer's wallet locks exactly the amount its owner
//! confirmed, in a vault only the buyer's own code releases, and only for the seller named in the link (a letter's
//! sender is authenticated). The seller's wallet accepts only its own offer on its own terms and refuses a deadline
//! shorter than the one it offered. A letter that is lost changes nothing: the money is the buyer's again after the
//! deadline, and every step can be sent again.
//!
//! Nothing is stored. What a wallet needs after a restart is in the letters themselves (each repeats what came before
//! it) and in the vault's own sealed record. A wallet that posts a bond first writes itself a letter saying so, and
//! reads those before anything else, so a bond is never posted twice by a wallet restarted in between.

use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

const LINK_HEAD: &str = "monerousd:sale?";
const LETTER_HEAD: &str = "musd-sale/1 ";
const HOUR_MS: u64 = usdm_decider::whir_rec_block::CHAIN_HOUR_MS;

/// A purchase this wallet started this session: who sells, the offer, and the messages so far. A purchase is held in
/// one vault per note that funds it (a spend has one input and never joins notes), so the messages are lists: one
/// request, one acceptance, one notice and one code per part. Nearly always there is one part. A delivery bond is one
/// more request, the last, of kind "bond".
#[derive(Clone)]
struct Buying {
    seller: String,
    offer: serde_json::Value,
    requests: Vec<serde_json::Value>,
    fundeds: Vec<Option<serde_json::Value>>,
    /// A SUBSCRIPTION's period in hours (0 for a purchase): while this wallet stays open, the next period's payment
    /// is set aside as soon as the current period has started.
    period: u64,
    /// The deposit already paid for this purchase (it is paid once, when the price goes into escrow).
    deposit_paid: bool,
    /// The relay the buyer picks up at, and the custody bond's request and notice once made.
    relay: Option<String>,
    custody: Option<(serde_json::Value, Option<serde_json::Value>)>,
    /// A DOWNLOAD's sealed content as this wallet checked it against the offer, before it locked any money.
    download: Option<digital::Checked>,
}

/// The most parts one purchase is held in: a bound on what one letter can make the other wallet compute.
// PRODUCTION-SCALE-REVIEWED: a bound on a message's list, the same in production; a wallet whose money is in more
// pieces than this is told so in words.
const MAX_PARTS: usize = 16;

fn id_of(v: &serde_json::Value) -> String {
    v.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string()
}

fn is_bond(request: &serde_json::Value) -> bool {
    request.get("of").and_then(|k| k.as_str()) == Some("bond")
}

fn amount_of(request: &serde_json::Value) -> u64 {
    request.get("amount").and_then(|a| a.as_u64()).unwrap_or(0)
}

fn list(v: &serde_json::Value, k: &str) -> Result<Vec<serde_json::Value>, String> {
    let l = v.get(k).and_then(|x| x.as_array()).cloned().ok_or_else(|| format!("a sale letter has no `{k}`"))?;
    if l.is_empty() || l.len() > MAX_PARTS + 1 {
        return Err("a sale letter lists too many or no parts".to_string());
    }
    Ok(l)
}

/// BUYER: which purchase (by its first part's id) each held part belongs to, so the page shows one row per purchase.
pub fn groups() -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (sale, b) in locked(&BUYING).iter() {
        for r in b.requests.iter().chain(b.custody.as_ref().map(|(r, _)| r)) {
            out.insert(id_of(r), serde_json::Value::String(sale.clone()));
        }
    }
    serde_json::Value::Object(out)
}

/// O1-FOOTPRINT-REVIEWED: RAM only; one entry per purchase or sale of this session, gone when the wallet closes.
static BUYING: LazyLock<Mutex<HashMap<String, Buying>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// The buyer of each sale this wallet answered this session (to send a refund code to).
static BUYERS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// The offers made this session, for the seller's "waiting for a buyer" list.
static OFFERS: LazyLock<Mutex<Vec<serde_json::Value>>> = LazyLock::new(|| Mutex::new(Vec::new()));
/// Letters already acted on this session, by their content hash.
static DONE: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
/// Bonds this wallet has said it is posting (its own letters to itself): never posted a second time.
static POSTED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
/// SELLER: the deposit each sale expects: sale id → (reference, amount).
static DEPOSITS: LazyLock<Mutex<HashMap<String, ([u8; 16], u64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// RELAY: pickups this wallet agreed to hold: bond id → (buyer, title).
static PICKUPS: LazyLock<Mutex<HashMap<String, (String, String)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// BUYER: one download that arrived. It is written to the device's downloads folder the moment its key opens it, so a
/// paid-for file never waits in memory for a tap; `bytes` are held only when that write failed, until it succeeds.
struct Download {
    title: String,
    name: String,
    size: usize,
    /// Where the file was written, once it was.
    saved: Option<std::path::PathBuf>,
    bytes: Vec<u8>,
}
/// BUYER: downloads that have arrived: sale id → the file.
/// O1-FOOTPRINT-REVIEWED: RAM only, and a row holds a file's bytes only while its write to disk has not succeeded
/// (each at most `digital::FILE_MAX`); a row leaves when its owner dismisses it or the wallet closes.
static DOWNLOADS: LazyLock<Mutex<HashMap<String, Download>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// BUYER: the parcel pinned for each purchase: sale id → (tracking number, when it was pinned in unix seconds). One
/// number an order: the first its buyer ACCEPTED. O1-FOOTPRINT-REVIEWED: RAM only, one entry per open purchase.
static PINS: LazyLock<Mutex<HashMap<String, (String, u64)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// BUYER: a tracking number a seller named and this wallet's owner has not accepted: sale id → tracking number. It
/// proves nothing and releases nothing. O1-FOOTPRINT-REVIEWED: RAM only, one entry per open purchase.
static PIN_OFFERS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// SELLER: the download parts this wallet has taken with its key this session (each is taken once).
static DELIVERED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
/// RELAY: does this wallet take pickups? Off at every start; its owner switches it on.
static RELAY_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn own_handle() -> Result<String, String> {
    letter_address_impl()?.get("address").and_then(|a| a.as_str()).map(String::from).ok_or_else(|| "no wallet open".to_string())
}

/// A title as it travels in a link: letters, digits and a few marks, spaces as `+`, at most 60 characters.
fn title_out(title: &str) -> String {
    let kept: String = title.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ',')).take(60).collect();
    let trimmed = kept.split_whitespace().collect::<Vec<_>>().join("+");
    if trimmed.is_empty() {
        "Sale".to_string()
    } else {
        trimmed
    }
}

fn title_in(t: &str) -> String {
    t.replace('+', " ")
}

/// An offer's terms, as the link states them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Terms {
    amount: u64,
    hours: u64,
    period: u64,
    deposit: u64,
    bond: u64,
    title: String,
    /// A download: what the link states about its sealed content.
    dl: Option<digital::Listing>,
}

/// The seller's mark over an offer: only the wallet that made the offer can produce or check it.
fn offer_mark(t: &Terms, nonce: &str, title_in_link: &str) -> Result<String, String> {
    let out_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).ok_or_else(|| "no wallet open".to_string())?;
    let key = blake3::derive_key("MonerousD 2026-11-10 sale offer mark v2", &out_sk);
    let mut h = blake3::Hasher::new_keyed(&key);
    for v in [t.amount, t.hours, t.period, t.deposit, t.bond] {
        h.update(&v.to_le_bytes());
    }
    h.update(nonce.as_bytes());
    h.update(&[0]);
    h.update(title_in_link.as_bytes());
    if let Some(dl) = &t.dl {
        // a download's four fields, each a fixed-width hex word: the mark covers what the buyer will check against
        for f in [&dl.root, &dl.lock, &dl.salt, &dl.bundle] {
            h.update(&[1]);
            h.update(f.as_bytes());
        }
    }
    Ok(hex::encode(&h.finalize().as_bytes()[..16]))
}

/// An offer's fields as one object: `{s, a, h, p, n, k, t}` and `d`, `b` (zero when the link leaves them out).
fn offer_fields(link: &str) -> Result<serde_json::Value, String> {
    let query = link.trim().strip_prefix(LINK_HEAD).ok_or_else(|| "that is not a MonerousD sale link".to_string())?;
    let mut f = serde_json::Map::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or_else(|| "the sale link is malformed".to_string())?;
        let ok = !v.is_empty() && v.len() <= 4096 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'+' | b'-' | b'_' | b'.' | b','));
        if !ok || !matches!(k, "s" | "a" | "h" | "p" | "n" | "k" | "t" | "d" | "b" | "x" | "l" | "c" | "v") {
            return Err("the sale link is malformed".to_string());
        }
        f.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    for k in ["d", "b"] {
        f.entry(k.to_string()).or_insert_with(|| serde_json::Value::String("0".to_string()));
    }
    let v = serde_json::Value::Object(f);
    for k in ["s", "a", "h", "p", "n", "k", "t"] {
        if v.get(k).is_none() {
            return Err("the sale link is incomplete".to_string());
        }
    }
    Ok(v)
}

fn num(offer: &serde_json::Value, k: &str) -> Result<u64, String> {
    offer.get(k).and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| "the sale link is malformed".to_string())
}

fn word<'a>(offer: &'a serde_json::Value, k: &str) -> &'a str {
    offer.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The terms an offer states. A link written before deposits and bonds existed states none.
fn terms_of(offer: &serde_json::Value) -> Result<Terms, String> {
    let zero_or = |k: &str| if offer.get(k).is_some() { num(offer, k) } else { Ok(0) };
    let hexword = |k: &str, bytes: usize| -> Result<String, String> {
        let w = word(offer, k);
        (w.len() == 2 * bytes && w.bytes().all(|b| b.is_ascii_hexdigit())).then(|| w.to_ascii_lowercase()).ok_or_else(|| "the sale link is malformed".to_string())
    };
    let dl = if ["x", "l", "c", "v"].iter().any(|k| offer.get(*k).is_some()) {
        Some(digital::Listing { root: hexword("x", 32)?, lock: hexword("l", 32)?, salt: hexword("c", 16)?, bundle: hexword("v", 32)? })
    } else {
        None
    };
    let t = Terms { amount: num(offer, "a")?, hours: num(offer, "h")?, period: num(offer, "p")?, deposit: zero_or("d")?, bond: zero_or("b")?, title: title_in(word(offer, "t")), dl };
    terms_ok(&t)?;
    Ok(t)
}

fn terms_ok(t: &Terms) -> Result<(), String> {
    if t.amount <= P2P_FEE_ATOMIC {
        return Err("the price is too small to protect".to_string());
    }
    if t.period == 0 && (t.hours == 0 || t.hours > 24 * 365) {
        return Err("choose a delivery deadline between one hour and a year".to_string());
    }
    if t.period != 0 && !(24..=24 * 366).contains(&t.period) {
        return Err("a subscription repeats between daily and yearly".to_string());
    }
    if t.period != 0 && (t.deposit != 0 || t.bond != 0) {
        return Err("a subscription has no deposit and no delivery bond".to_string());
    }
    if t.deposit != 0 && t.amount.saturating_sub(t.deposit) <= 4 * P2P_FEE_ATOMIC {
        return Err("the deposit must leave part of the price in escrow".to_string());
    }
    if t.bond != 0 && (t.bond <= P2P_FEE_ATOMIC || t.bond > t.amount) {
        return Err("a delivery bond is between the network fee and the price".to_string());
    }
    if t.dl.is_some() && (t.period != 0 || t.deposit != 0 || t.bond != 0) {
        return Err("a download has no subscription, deposit or delivery bond".to_string());
    }
    if t.dl.is_some() && t.hours < 2 {
        // the seller's wallet delivers only while more than an hour is left, so the buyer cannot take the payment back
        // while the key is on its way
        return Err("give a download at least two hours to be delivered".to_string());
    }
    Ok(())
}

/// SELLER: make a sale. `as_name` is this wallet's own @name when it has one, which makes the link short enough to
/// read out or show as a code; it is used only if the chain says it points at this wallet.
pub fn offer(title: &str, amount: u64, hours: u64, as_name: Option<&str>) -> Result<serde_json::Value, String> {
    offer_every(title, amount, hours, 0, as_name)
}

/// [`offer`], or with `period` hours a SUBSCRIPTION: the same amount again every period, each payment set aside by the
/// subscriber before its period starts and the merchant's from that moment.
pub fn offer_every(title: &str, amount: u64, hours: u64, period: u64, as_name: Option<&str>) -> Result<serde_json::Value, String> {
    offer_terms(title, amount, hours, period, 0, 0, as_name)
}

/// [`offer_every`] with a `deposit` (paid at the order, final) and a delivery `bond` (the seller's own money, locked
/// beside the buyer's and the buyer's if nothing is delivered). Either may be zero.
pub fn offer_terms(title: &str, amount: u64, hours: u64, period: u64, deposit: u64, bond: u64, as_name: Option<&str>) -> Result<serde_json::Value, String> {
    let t = title_out(title);
    offer_made(Terms { amount, hours, period, deposit, bond, title: title_in(&t), dl: None }, &t, None, as_name)
}

/// SELLER: sell the file `name` holding `bytes` as a DOWNLOAD. The file is sealed under a key only this wallet can
/// derive, its sealed bytes and one proof are stored on the Veil (the storage price is paid to the holders), and the
/// link that comes back is all a buyer needs. The buyer's wallet is handed the key by the spend that pays this wallet.
pub fn offer_download(title: &str, amount: u64, hours: u64, name: &str, bytes: &[u8], as_name: Option<&str>) -> Result<serde_json::Value, String> {
    use rand::RngCore as _;
    let t = title_out(title);
    terms_ok(&Terms { amount, hours, period: 0, deposit: 0, bond: 0, title: title_in(&t), dl: Some(digital::Listing { root: String::new(), lock: String::new(), salt: String::new(), bundle: String::new() }) })?;
    let mut raw = [0u8; 8];
    rand::rngs::OsRng.try_fill_bytes(&mut raw).map_err(|_| "this device gave no randomness".to_string())?;
    let nonce = hex::encode(raw);
    let store = |blob: &[u8]| -> Result<[u8; 32], String> {
        let stored = veil_site::store(blob)?;
        stored["root"].as_str().and_then(|r| hex::decode(r).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| "your node did not name the stored bytes".to_string())
    };
    let (bundle, [root, lock, salt]) = digital::seal_listing(&nonce, name, bytes, &store)?;
    let bundle_root = hex::encode(store(&bundle)?);
    let dl = digital::Listing { root, lock, salt, bundle: bundle_root };
    offer_made(Terms { amount, hours, period: 0, deposit: 0, bond: 0, title: title_in(&t), dl: Some(dl) }, &t, Some(nonce), as_name)
}

/// Write the link for `terms` (whose title travels as `t`) under `nonce` (a fresh one when `None`).
fn offer_made(terms: Terms, t: &str, nonce: Option<String>, as_name: Option<&str>) -> Result<serde_json::Value, String> {
    use rand::RngCore as _;
    let (amount, hours, period, deposit, bond) = (terms.amount, terms.hours, terms.period, terms.deposit, terms.bond);
    terms_ok(&terms)?;
    let mine = own_handle()?;
    let seller = match as_name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) if resolve_recipient(&format!("@{}", name.trim_start_matches('@'))).ok().as_deref() == Some(mine.as_str()) => {
            format!("@{}", name.trim_start_matches('@'))
        }
        _ => mine,
    };
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let mut raw = [0u8; 8];
            rand::rngs::OsRng.try_fill_bytes(&mut raw).map_err(|_| "this device gave no randomness".to_string())?;
            hex::encode(raw)
        }
    };
    let k = offer_mark(&terms, &nonce, t)?;
    let mut link = format!("{LINK_HEAD}s={seller}&a={amount}&h={hours}&p={period}&n={nonce}&k={k}&t={t}");
    if deposit != 0 {
        link.push_str(&format!("&d={deposit}"));
    }
    if bond != 0 {
        link.push_str(&format!("&b={bond}"));
    }
    if let Some(dl) = &terms.dl {
        link.push_str(&format!("&x={}&l={}&c={}&v={}", dl.root, dl.lock, dl.salt, dl.bundle));
    }
    let made = serde_json::json!({
        "link": link, "short": seller.starts_with('@'), "title": terms.title, "amount_atomic": amount, "hours": hours, "period": period,
        "deposit_atomic": deposit, "bond_atomic": bond, "nonce": nonce, "download": terms.dl.is_some(),
    });
    locked(&OFFERS).push(made.clone());
    Ok(made)
}

/// SELLER: the offers made this session.
pub fn offers() -> Vec<serde_json::Value> {
    locked(&OFFERS).clone()
}

/// BUYER: what a sale link offers, in the one sentence the buyer confirms. Nothing is sent.
pub fn read(link: &str) -> Result<serde_json::Value, String> {
    let f = offer_fields(link)?;
    let t = terms_of(&f)?;
    let seller = word(&f, "s");
    let who = if seller.starts_with('@') { seller.to_string() } else { "this seller".to_string() };
    let days = if t.hours % 24 == 0 { format!("{} day{}", t.hours / 24, if t.hours == 24 { "" } else { "s" }) } else { format!("{} hours", t.hours) };
    if t.period != 0 {
        let every = match t.period {
            24 => "day".to_string(),
            168 => "week".to_string(),
            720 | 744 => "month".to_string(),
            8760 => "year".to_string(),
            h if h % 24 == 0 => format!("{} days", h / 24),
            h => format!("{h} hours"),
        };
        return Ok(serde_json::json!({
            "mode": "subscription", "status": "open", "merchant": who, "title": t.title,
            "amount_atomic": t.amount, "amount_usdm": atomic_to_usdm(t.amount), "period": t.period,
            "sentence": format!(
                "Subscribe to {1} from {who}: ${0:.2} now, then ${0:.2} every {every}. Cancel any time; a payment for a period that has not started is refunded.",
                atomic_to_usdm(t.amount),
                approval_short(&t.title, 60)
            ),
        }));
    }
    if t.dl.is_some() {
        return Ok(serde_json::json!({
            "mode": "download", "status": "open", "merchant": who, "title": t.title,
            "amount_atomic": t.amount, "amount_usdm": atomic_to_usdm(t.amount), "hours": t.hours,
            "sentence": format!(
                "Buy {} from {who} for ${:.2}: a download. Your wallet checks the file's proof before it asks you to pay; the file's key arrives with your payment, or the payment returns within {days}.",
                approval_short(&t.title, 60),
                atomic_to_usdm(t.amount)
            ),
        }));
    }
    let mut sentence = format!(
        "Pay ${:.2} to {who} for {}. Held in escrow until you confirm receipt; refunded to you if it is not delivered within {days}.",
        atomic_to_usdm(t.amount),
        approval_short(&t.title, 60)
    );
    if t.deposit != 0 {
        sentence.push_str(&format!(" ${:.2} of it is a deposit: paid to the seller now and not refundable.", atomic_to_usdm(t.deposit)));
    }
    if t.bond != 0 {
        sentence.push_str(&format!(" The seller locks a ${:.2} delivery bond that becomes yours if it is not delivered.", atomic_to_usdm(t.bond)));
    }
    Ok(serde_json::json!({
        "mode": "protected", "status": "open", "merchant": who, "title": t.title,
        "amount_atomic": t.amount, "amount_usdm": atomic_to_usdm(t.amount), "hours": t.hours,
        "deposit_atomic": t.deposit, "bond_atomic": t.bond,
        "sentence": sentence,
    }))
}

fn send(to: &str, kind: &str, body: &serde_json::Value) -> Result<(), String> {
    letter_send_impl(to, &format!("{LETTER_HEAD}{kind} {body}")).map(|_| ())
}

/// The reference a sale's deposit payment carries: both wallets compute it from the offer and the sale's id.
fn deposit_reference(offer: &serde_json::Value, sale: &str) -> [u8; 16] {
    let mut h = blake3::Hasher::new_derive_key("MonerousD 2026-11-10 sale deposit v1");
    h.update(word(offer, "n").as_bytes());
    h.update(&[0]);
    h.update(sale.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize().as_bytes()[..16]);
    out
}

/// BUYER: buy what the link offers. `approve` is asked the one sentence first. The request goes to the seller's wallet;
/// the money is locked by [`sync`] the moment the seller's wallet answers. `relay` is a pickup point the buyer chose
/// (a @name or an address): its wallet is asked to hold the parcel under a custody bond.
pub fn buy(link: &str, relay: Option<&str>, approve: &dyn Fn(String) -> Result<(), String>) -> Result<serde_json::Value, String> {
    let offer = offer_fields(link)?;
    let shown = read(link)?;
    let t = terms_of(&offer)?;
    let seller = resolve_recipient(word(&offer, "s"))?;
    let me = own_handle()?;
    if seller == me {
        return Err("that is your own sale".to_string());
    }
    let relay = match relay.map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => {
            let at = resolve_recipient(r)?;
            if at == me || at == seller || t.period != 0 {
                return Err("choose a pickup relay that is neither you nor the seller".to_string());
            }
            Some(at)
        }
        None => None,
    };
    let mut sentence = shown["sentence"].as_str().unwrap_or("Buy this").to_string();
    if relay.is_some() {
        sentence.push_str(" Pickup at the relay you chose: it locks a bond worth the price while it holds your parcel.");
    }
    // A DOWNLOAD: read the sealed content and check its proof BEFORE the buyer is asked, so the sentence says what was
    // checked. A large file's sealed bytes are read now too: a key for bytes this wallet cannot get is worth nothing.
    let download = match &t.dl {
        Some(dl) => {
            if relay.is_some() {
                return Err("a download is not picked up at a relay".to_string());
            }
            let bundle = veil_site::read(&dl.bundle, 180).map_err(|e| format!("this download's sealed content could not be read: {e} Nothing was sent."))?;
            let checked = digital::check_bundle(&bundle, dl)?;
            if let Some(large) = &checked.large {
                veil_site::read(&hex::encode(large.sealed_root), 600).map_err(|e| format!("this download's file could not be read: {e} Nothing was sent."))?;
            }
            let days = if t.hours % 24 == 0 { format!("{} day{}", t.hours / 24, if t.hours == 24 { "" } else { "s" }) } else { format!("{} hours", t.hours) };
            let who = shown["merchant"].as_str().unwrap_or("this seller").to_string();
            sentence = digital::sentence(&checked, &who, &t.title, t.amount, &days);
            Some(checked)
        }
        None => None,
    };
    approve(sentence)?;
    let now = node_chain_time_ms();
    if now == 0 {
        return Err("your node did not answer. Nothing was sent. Try again in a moment.".to_string());
    }
    // a subscription's first period starts now (the merchant collects it within the hour); a purchase is held for `h`
    let (due, kind) = if t.period != 0 { (now, "sub") } else { (now.saturating_add(t.hours.saturating_mul(HOUR_MS)), "") };
    // one part per note that funds the purchase: one, unless no single note covers what goes into escrow
    let parts = vault_ops::parts_for(t.amount - t.deposit)?;
    if parts.len() > MAX_PARTS || (t.period != 0 && parts.len() != 1) {
        return Err("your money is in too many small pieces for this. Nothing was sent.".to_string());
    }
    let mut requests = match &t.dl {
        // a download: every part is locked under the listing's one delivery lock
        Some(dl) => parts.iter().map(|a| vault_ops::key_request(&t.title, *a, due, &dl.lock)).collect::<Result<Vec<_>, _>>()?,
        None => parts.iter().map(|a| vault_ops::order_request_kind(&t.title, *a, due, kind)).collect::<Result<Vec<_>, _>>()?,
    };
    if t.bond != 0 {
        // the seller's delivery bond: this wallet holds its key and is the one the clock pays
        requests.push(vault_ops::bond_request(&t.title, t.bond, due, None)?);
    }
    let id = id_of(&requests[0]);
    locked(&BUYING).insert(
        id.clone(),
        Buying { seller: seller.clone(), offer: offer.clone(), requests: requests.clone(), fundeds: vec![None; requests.len()], period: t.period, deposit_paid: false, relay, custody: None, download },
    );
    send(&seller, "request", &serde_json::json!({ "offer": offer, "requests": requests }))?;
    Ok(serde_json::json!({ "id": id, "waiting_for_seller": true, "amount_atomic": t.amount, "parts": parts.len() }))
}

/// BUYER: confirm receipt. The codes go to the seller's wallet (and the relay's, for a pickup), which take their money
/// with them. From a wallet that was closed since the purchase, the caller shows the code instead
/// (`vault_ops::order_code`).
pub fn i_have_it(id: &str) -> Result<serde_json::Value, String> {
    let b = locked(&BUYING)
        .values()
        .find(|b| b.requests.iter().any(|r| id_of(r) == id))
        .cloned()
        .ok_or_else(|| "this wallet was closed since that purchase: show the seller your code instead".to_string())?;
    let fundeds = b.fundeds.iter().cloned().collect::<Option<Vec<_>>>().ok_or_else(|| "the money for that purchase is not all held yet".to_string())?;
    let codes = b.requests.iter().map(|r| vault_ops::order_code(&id_of(r))).collect::<Result<Vec<_>, _>>()?;
    send(&b.seller, "code", &serde_json::json!({ "offer": b.offer, "requests": b.requests, "fundeds": fundeds, "codes": codes }))?;
    if let (Some(relay), Some((request, Some(funded)))) = (b.relay.as_ref(), b.custody.as_ref()) {
        let code = vault_ops::order_code(&id_of(request))?;
        send(relay, "custody-code", &serde_json::json!({ "title": title_in(word(&b.offer, "t")), "request": request, "funded": funded, "code": code }))?;
    }
    Ok(serde_json::json!({ "sent": true }))
}

/// SELLER: call a sale off. The refund code goes to the buyer's wallet, which takes the money back by itself.
pub fn call_off(id: &str) -> Result<serde_json::Value, String> {
    let code = vault_ops::order_refund_code(id)?;
    match locked(&BUYERS).get(id).cloned() {
        Some(buyer) => {
            send(&buyer, "refund", &serde_json::json!({ "code": code }))?;
            Ok(serde_json::json!({ "sent": true }))
        }
        None => Ok(serde_json::json!({ "sent": false, "code": code })),
    }
}

/// Is this offer one THIS wallet made, unaltered? The seller's whole memory of an offer is this check.
fn own_offer(offer: &serde_json::Value) -> Result<Terms, String> {
    let t = terms_of(offer)?;
    if offer_mark(&t, word(offer, "n"), word(offer, "t"))? != word(offer, "k") {
        return Err("that request is not for a sale this wallet offered".to_string());
    }
    Ok(t)
}

/// Do these requests ask for exactly what the offer states: the escrowed price in the purchase parts, and the delivery
/// bond (one request, when the offer has one) in a bond part?
fn requests_match(t: &Terms, requests: &[serde_json::Value]) -> bool {
    let price = requests.iter().filter(|r| !is_bond(r)).try_fold(0u64, |sum, r| sum.checked_add(amount_of(r)));
    let bonds: Vec<u64> = requests.iter().filter(|r| is_bond(r)).map(amount_of).collect();
    let bond_ok = if t.bond == 0 { bonds.is_empty() } else { bonds == [t.bond] };
    // a download's parts are locked under the listing's delivery lock and nothing else; a purchase's never are
    let kind_ok = requests.iter().filter(|r| !is_bond(r)).all(|r| {
        let key = r.get("of").and_then(|k| k.as_str()) == Some("key");
        match &t.dl {
            Some(dl) => key && r.get("lock").and_then(|l| l.as_str()) == Some(dl.lock.as_str()),
            None => !key,
        }
    });
    price == Some(t.amount - t.deposit) && bond_ok && kind_ok
}

/// SELLER: the key and salt of a download this wallet listed, re-derived from the offer's nonce. `None` when they are
/// not the listing's (the offer is another wallet's, or was altered): the wallet then delivers nothing.
fn own_listing_secrets(offer: &serde_json::Value, dl: &digital::Listing) -> Option<(usdm_decider::whir_rec_block::VaultSecret, usdm_decider::whir_rec_block::ListingSalt)> {
    let (key, salt) = digital::listing_secrets(word(offer, "n")).ok()?;
    let locks = usdm_decider::whir_rec_block::delivery_locks(&own_note_keys().ok()?.spk, &key, &salt);
    (vault_ops::delivery_lock_hex(&locks) == dl.lock && vault_ops::lanes_hex(&salt) == dl.salt).then_some((key, salt))
}

/// BUYER: a download's key arrived (read from the seller's spend, or sent in the seller's letter). The file is opened
/// and kept until it is saved. `checked` is the sealed content this wallet checked against the offer.
fn take_key(sale: &str, title: &str, checked: &digital::Checked, key: &usdm_decider::whir_rec_block::VaultSecret) -> Result<String, String> {
    let read_large = |root: &[u8; 32]| veil_site::read(&hex::encode(root), 600);
    let (name, bytes) = digital::open(checked, key, &read_large)?;
    let saved = save_file(&name, &bytes).ok();
    let said = match &saved {
        Some(path) => format!("Your download is saved: {}.", path.display()),
        None => format!("Your download is ready: {name}. Save it from the Wallet page."),
    };
    let held = if saved.is_some() { Vec::new() } else { bytes.clone() };
    locked(&DOWNLOADS).insert(sale.to_string(), Download { title: title.to_string(), name, size: bytes.len(), saved, bytes: held });
    Ok(said)
}

/// Where a bought file is written: the folder `MONEROUSD_DOWNLOADS` names when it is set, else the device's Downloads
/// folder, its Documents folder, or (a device with neither) a Downloads folder beside the wallet's own data.
fn downloads_folder() -> Option<std::path::PathBuf> {
    std::env::var_os("MONEROUSD_DOWNLOADS")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(dirs::download_dir)
        .or_else(dirs::document_dir)
        .or_else(|| dirs::data_dir().map(|d| d.join("MonerousD").join("Downloads")))
}

/// A file name that is only a name. The SELLER chose it, so it is never trusted as a path: no folder separators, no
/// control characters, no leading dot (a hidden file), no characters a file system refuses.
fn safe_file_name(name: &str) -> String {
    let clean: String = name.chars().map(|c| if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c }).collect();
    let clean = clean.trim().trim_start_matches('.').trim().to_string();
    if clean.is_empty() { "download".to_string() } else { clean }
}

/// Write a bought file to the downloads folder and return where. NEVER over a file already there: a taken name gets
/// " (1)", " (2)" … before its extension, and the file is created only if no file of that name exists.
///
/// LOCAL-STORAGE-REQUIRED: the file IS what the buyer paid for, and handing it to its owner means putting it in the
/// owner's own folder; no proof, DA record, wire field or RAM shape can stand in for a document a person opens in
/// another program. It is the user's file, not wallet or node state: nothing here ever reads it back, and no
/// balance, key, note or decision depends on it.
/// bound: one file per download the user bought, its size the file's own (at most `digital::FILE_MAX`, 64 MiB);
/// nothing per block, per note or per height is written, and the wallet's own state on disk does not change.
fn save_file(name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    save_file_in(&downloads_folder().ok_or_else(|| "this device has no folder to save to".to_string())?, name, bytes)
}

/// [`save_file`] into `folder`.
///
/// LOCAL-STORAGE-REQUIRED: the one write of a bought file into its owner's folder, as [`save_file`] states: the
/// file is the purchase itself, a document a person opens in another program, and nothing reads it back.
/// bound: one file per download the user bought, at most `digital::FILE_MAX` (64 MiB); nothing per block, per note
/// or per height.
fn save_file_in(folder: &std::path::Path, name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    use std::io::Write as _;
    std::fs::create_dir_all(folder).map_err(|e| format!("the downloads folder could not be opened: {e}"))?;
    let clean = safe_file_name(name);
    let (stem, ext) = match clean.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), format!(".{ext}")),
        _ => (clean.clone(), String::new()),
    };
    let mut copy = 0u32;
    loop {
        let path = folder.join(if copy == 0 { clean.clone() } else { format!("{stem} ({copy}){ext}") });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| format!("the file could not be written: {e}"))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => copy = copy.checked_add(1).ok_or_else(|| "the downloads folder is full of files of that name".to_string())?,
            Err(e) => return Err(format!("the file could not be written: {e}")),
        }
    }
}

/// How much of a deposit this wallet has received: its own notes that name the deposit's reference.
fn deposit_received(reference: &[u8; 16]) -> u64 {
    let Ok(dk) = own_scan_dk() else { return 0 };
    let s = SCAN.lock().unwrap_or_else(|e| e.into_inner());
    s.as_ref()
        .map(|st| st.owned.iter().filter(|n| n.asset == pq::USDM_ASSET_TAG && pq::note_carries_reference(&n.note, &dk, reference)).fold(0u64, |sum, n| sum.saturating_add(n.amount)))
        .unwrap_or(0)
}

/// POSTER: post a bond exactly once. The note-to-self goes first: a wallet restarted between the two finds the note
/// and never posts again (the bond is then missing, which the other side sees; it is never doubled).
fn post_once(id: &str) -> Result<(), String> {
    if !locked(&POSTED).insert(id.to_string()) {
        return Ok(());
    }
    send(&own_handle()?, "bondpost", &serde_json::json!({ "id": id }))?;
    vault_ops::bond_post(id).map(|_| ())
}

/// One letter, acted on. `Ok(Some(line))` says in words what happened; `Ok(None)` is a letter that needs nothing;
/// `Err` is "not now" (a node still catching up), and the letter is looked at again on the next pass.
fn handle(kind: &str, from: &str, v: &serde_json::Value) -> Result<Option<String>, String> {
    let part = |k: &str| v.get(k).cloned().ok_or_else(|| format!("a sale letter has no `{k}`"));
    let text = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").chars().take(128).collect::<String>();
    match kind {
        // SELLER: a buyer asks. Accept only this wallet's own offer, on its terms, with no shorter deadline.
        "request" => {
            let (offer, requests) = (part("offer")?, list(v, "requests")?);
            let Ok(t) = own_offer(&offer) else { return Ok(None) };
            let now = node_chain_time_ms();
            if now == 0 {
                return Err("the node did not answer".to_string());
            }
            let title = t.title.clone();
            if !requests_match(&t, &requests) {
                return Ok(Some(format!("An order for {title} at the wrong price was declined.")));
            }
            // THE BUYER CHOSE THE HOUR on each request; the offer's own terms decide whether it stands. Not sooner than
            // offered (a purchase's deadline is when the buyer takes the money back alone). And NOT LATER: a
            // subscription's hour is when this wallet may collect, so a subscriber naming a start months ahead would
            // show a locked payment that can be cancelled before it is ever collected; a purchase's later deadline
            // would hold this wallet's own delivery bond that much longer. The two wallets read one chain clock, so an
            // honest request is within the hour either way; two hours are allowed.
            let hours_of = |r: &serde_json::Value| r.get("t_h").and_then(|t| t.as_u64()).unwrap_or(0).saturating_mul(HOUR_MS);
            let (soonest, latest) = (requests.iter().map(hours_of).min().unwrap_or(0), requests.iter().map(hours_of).max().unwrap_or(u64::MAX));
            let hold = if t.period != 0 { 0 } else { t.hours };
            let offered = now.saturating_add(hold.saturating_mul(HOUR_MS));
            if soonest.saturating_add(HOUR_MS) < offered {
                return Ok(Some(format!("An order for {title} with a shorter delivery deadline than you offered was declined.")));
            }
            if latest > offered.saturating_add(2 * HOUR_MS) {
                return Ok(Some(format!("An order for {title} with a later date than you offered was declined.")));
            }
            let Ok(accepts) = requests.iter().map(|r| vault_ops::order_accept(r, amount_of(r), &title)).collect::<Result<Vec<_>, _>>() else {
                return Ok(None);
            };
            for a in &accepts {
                locked(&BUYERS).insert(id_of(a), from.to_string());
            }
            // ⛔ AUDIT F11 (2026-11-10): where a DEPOSIT is paid. It went to the address the offer names, which is this
            // wallet's letter address: an address with no locator, so the deposit arrived as a note this wallet could
            // see while open and could neither spend nor find again from its recovery phrase (measured on real nodes
            // for the same shape, a payment to a @username). The accept goes to this one buyer privately, so it carries
            // this wallet's own receive address, the kind every ordinary payment is found and spent by.
            let pay_to = if t.deposit != 0 {
                wallet_address()?.get("address").and_then(|a| a.as_str()).map(String::from).ok_or_else(|| "no wallet address".to_string())?
            } else {
                String::new()
            };
            send(from, "accept", &serde_json::json!({ "accepts": accepts, "pay_to": pay_to }))?;
            Ok(Some(format!("New order for {title}: payment pending.")))
        }
        // BUYER: the seller's wallet accepted. Lock the money the owner already confirmed, for that seller only. A part
        // that cannot be locked this moment (a node catching up) is tried again on the next pass; parts already locked
        // are kept. Then the deposit, once.
        "accept" => {
            let accepts = list(v, "accepts")?;
            let sale = id_of(&accepts[0]);
            let Some(b) = locked(&BUYING).get(&sale).cloned() else { return Ok(None) };
            let t = terms_of(&b.offer)?;
            let settled = b.fundeds.iter().all(Option::is_some) && (t.deposit == 0 || b.deposit_paid);
            if b.seller != from || accepts.len() != b.requests.len() || settled {
                return Ok(None);
            }
            for (i, accept) in accepts.iter().enumerate() {
                if b.fundeds[i].is_some() || id_of(accept) != id_of(&b.requests[i]) {
                    continue;
                }
                let funded = vault_ops::order_fund(accept)?;
                if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                    entry.fundeds[i] = Some(funded);
                }
            }
            let Some(now) = locked(&BUYING).get(&sale).cloned() else { return Ok(None) };
            let Some(fundeds) = now.fundeds.iter().cloned().collect::<Option<Vec<_>>>() else { return Err("a part is not locked yet".to_string()) };
            if t.deposit != 0 && !now.deposit_paid {
                // marked paid BEFORE it is sent: a deposit is never paid twice, and one that failed to send is retried
                if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                    entry.deposit_paid = true;
                }
                // paid to the address the seller's own accept names (audit F11), never to the offer's letter address:
                // the send door refuses an address its owner could not find the money at, so a seller's wallet that
                // names none is not paid a deposit at all and the letter is looked at again on the next pass
                let pay_to = v.get("pay_to").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if pay_to.is_empty() {
                    if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                        entry.deposit_paid = false;
                    }
                    return Err("the seller's wallet named no address for the deposit".to_string());
                }
                if let Err(e) = wallet_send_atomic_referenced_blocking(pay_to, t.deposit, deposit_reference(&now.offer, &sale)) {
                    if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                        entry.deposit_paid = false;
                    }
                    return Err(e);
                }
            }
            // the money is held whether or not this notice arrives; the code letter repeats it
            let _ = send(from, "funded", &serde_json::json!({ "offer": now.offer, "requests": now.requests, "fundeds": fundeds }));
            // a pickup: ask the relay to hold the parcel under a custody bond the SELLER is paid from
            if let (Some(relay), None) = (now.relay.as_ref(), now.custody.as_ref()) {
                let seller_spk = accepts[0].get("seller_spk").and_then(|s| s.as_str()).unwrap_or("");
                let due = now.requests[0].get("t_h").and_then(|h| h.as_u64()).unwrap_or(0).saturating_mul(HOUR_MS);
                let request = vault_ops::bond_request(&t.title, t.amount, due, Some(seller_spk))?;
                if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                    entry.custody = Some((request.clone(), None));
                }
                let _ = send(relay, "custody-request", &serde_json::json!({ "title": t.title, "request": request }));
            }
            Ok(Some("Your payment is in escrow for this purchase.".to_string()))
        }
        // SELLER: the buyer says the money is locked. Recompute each vault; the wallet's own node says when it is held.
        "funded" | "code" => {
            let (offer, requests, fundeds) = (part("offer")?, list(v, "requests")?, list(v, "fundeds")?);
            let Ok(t) = own_offer(&offer) else { return Ok(None) };
            let title = t.title.clone();
            if !requests_match(&t, &requests) || requests.len() != fundeds.len() {
                return Ok(None);
            }
            for (request, funded) in requests.iter().zip(&fundeds) {
                let st = vault_ops::order_funded(request, funded, &title)?;
                locked(&BUYERS).insert(id_of(&st), from.to_string());
            }
            let sale = id_of(&requests[0]);
            if t.deposit != 0 {
                locked(&DEPOSITS).insert(sale.clone(), (deposit_reference(&offer, &sale), t.deposit));
            }
            let in_escrow = |r: &serde_json::Value| vault_ops::order_status(&id_of(r)).is_ok_and(|st| st["locked"] == true);
            if let Some(dl) = &t.dl {
                // A DOWNLOAD: this wallet is paid by handing the key over. Each part is taken with the content key the
                // moment this wallet's own node holds it; the key also goes by letter, for a buyer whose node was off.
                let Some((key, salt)) = own_listing_secrets(&offer, dl) else { return Ok(None) };
                // each part is taken once, as soon as it is in escrow; a part still on its way is tried on the next pass
                let mut waiting = false;
                for request in &requests {
                    let id = id_of(request);
                    if locked(&DELIVERED).contains(&id) {
                        continue;
                    }
                    if !in_escrow(request) {
                        waiting = true;
                        continue;
                    }
                    vault_ops::order_deliver(&id, key, salt)?;
                    locked(&DELIVERED).insert(id);
                }
                if waiting {
                    return Err("part of the buyer's payment is not in escrow yet".to_string());
                }
                let _ = send(from, "key", &serde_json::json!({ "offer": offer, "sale": sale, "key": vault_ops::lanes_hex(&key) }));
                return Ok(Some(format!("Paid: {title}. The buyer has the download's key.")));
            }
            if kind == "funded" {
                if let Some(bond) = requests.iter().find(|r| is_bond(r)) {
                    // this wallet's own money goes in only after its own node holds the buyer's
                    if !requests.iter().filter(|r| !is_bond(r)).all(in_escrow) {
                        return Err("the buyer's payment is not in escrow yet".to_string());
                    }
                    post_once(&id_of(bond))?;
                    return Ok(Some(format!("Payment for {title} is in escrow. Your delivery bond is locked.")));
                }
                return Ok(Some(format!("Payment for {title} is going into escrow.")));
            }
            let codes = list(v, "codes")?;
            if codes.len() != requests.len() || !codes.iter().all(|c| c.as_str().is_some_and(|c| vault_ops::order_code_is_good(c).unwrap_or(false))) {
                return Ok(Some(format!("A wrong code arrived for {title}. Nothing was taken.")));
            }
            for (request, code) in requests.iter().zip(codes.iter().filter_map(|c| c.as_str())) {
                // a bond this wallet never managed to post has nothing to take back
                if is_bond(request) && !in_escrow(request) {
                    continue;
                }
                vault_ops::order_release(code)?;
            }
            Ok(Some(format!("Paid: {title}.")))
        }
        // BUYER: the seller's letter with a download's key (the same key its payment published on the chain). Taken only
        // if it is the key of the lock the offer states and it opens the sealed content this wallet checks again here.
        "key" => {
            let offer = part("offer")?;
            let t = terms_of(&offer)?;
            let Some(dl) = &t.dl else { return Ok(None) };
            if resolve_recipient(word(&offer, "s")).ok().as_deref() != Some(from) {
                return Ok(None);
            }
            let Ok(key) = vault_ops::lanes_of_hex(&text("key")) else { return Ok(None) };
            let sale = text("sale");
            if locked(&DOWNLOADS).contains_key(&sale) {
                return Ok(None);
            }
            let held = locked(&BUYING).get(&sale).and_then(|b| b.download.clone());
            let checked = match held {
                Some(c) => c,
                // This wallet was closed since it paid. The letter's offer is the SELLER's word, so it is used only
                // if its delivery lock is the one this wallet locked its money under, by its own record of the
                // purchase: a key for some other listing of the seller's opens nothing here. Then the sealed content
                // is read and checked again.
                None => {
                    if !vault_ops::key_lock_is(&sale, &dl.lock) {
                        return Ok(Some(format!("A key letter arrived that is not for what {} was bought under. It was not used.", t.title)));
                    }
                    digital::check_bundle(&veil_site::read(&dl.bundle, 180)?, dl)?
                }
            };
            if !digital::key_fits(&checked, &key) {
                return Ok(Some(format!("A wrong key arrived for {}. It was not used.", t.title)));
            }
            let said = take_key(&sale, &t.title, &checked, &key)?;
            // In the session that bought it, the purchase's parts are over once the key is here. A wallet reopened
            // since keeps its own record of each part instead: whether the seller has taken a part is the chain's
            // answer, and a part the seller never takes stays the buyer's to take back at the deadline.
            finish_download(&sale);
            Ok(Some(said))
        }
        // BUYER: the seller names a parcel. ⛔ NEVER PINNED BY THIS LETTER: the seller chose the number, so it could
        // be any parcel that will be delivered anywhere. It is kept as an offer for the owner to accept
        // (`accept_tracking`), and is not kept at all when this build holds no carrier's key (no delivery proof could
        // be accepted, so there is nothing to offer). The first number a seller names is the one offered.
        "shipped" => {
            let (sale, tracking) = (text("sale"), text("tracking"));
            let Some(b) = locked(&BUYING).get(&sale).cloned() else { return Ok(None) };
            let tracking: String = tracking.chars().filter(char::is_ascii_alphanumeric).take(40).collect();
            if b.seller != from || tracking.len() < 8 || b.period != 0 || b.download.is_some() || accepted_carriers().is_empty() {
                return Ok(None);
            }
            if locked(&PINS).contains_key(&sale) {
                return Ok(None);
            }
            let offered = locked(&PIN_OFFERS).entry(sale.clone()).or_insert(tracking).clone();
            Ok(Some(format!(
                "{}: the seller says it shipped as parcel {offered}. Accept that number on your Wallet page only if the carrier's own page shows it going to your address.",
                title_in(word(&b.offer, "t"))
            )))
        }
        // SELLER: the buyer's wallet pinned the parcel.
        "pinned" => {
            if locked(&BUYERS).get(&text("sale")).map(String::as_str) != Some(from) {
                return Ok(None);
            }
            Ok(Some(format!("The buyer's wallet pinned parcel {}. A delivery notice for it will be accepted as proof.", text("tracking"))))
        }
        // BUYER: the seller's proof that the carrier delivered the pinned parcel. Checked against the carrier's key THIS
        // wallet holds; when it checks out, receipt is confirmed exactly as a tap on Confirm receipt would.
        "delivered" => {
            let sale = text("sale");
            let Some(b) = locked(&BUYING).get(&sale).cloned() else { return Ok(None) };
            let Some((tracking, pinned_at)) = locked(&PINS).get(&sale).cloned() else { return Ok(None) };
            if b.seller != from {
                return Ok(None);
            }
            let title = title_in(word(&b.offer, "t"));
            let Ok(shown) = serde_json::from_value::<notice::Shown>(part("shown")?) else { return Ok(None) };
            let root = text("proof");
            if root.len() != 64 || !root.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Ok(None);
            }
            let proof = veil_site::read(&root, 60)?;
            match notice::check(&notice::carriers(), &sale, &tracking, pinned_at, &shown, &proof) {
                Ok(carrier) => {
                    i_have_it(&sale)?;
                    Ok(Some(format!("{title}: {carrier} delivered it. Your payment was released to the seller.")))
                }
                Err(why) => Ok(Some(format!("{title}: a delivery proof arrived and was not accepted ({why}). Nothing was released."))),
            }
        }
        // BUYER: the seller called the sale off.
        "refund" => {
            let code = v.get("code").and_then(|c| c.as_str()).ok_or_else(|| "a refund letter has no code".to_string())?;
            vault_ops::order_refund(code)?;
            Ok(Some("A seller cancelled a sale. Your payment is being refunded.".to_string()))
        }
        // POSTER: this wallet's own note that it is posting a bond (read before every other letter, see `sync`).
        "bondpost" => {
            if own_handle().is_ok_and(|me| me == from) {
                locked(&POSTED).insert(id_of(v));
            }
            Ok(None)
        }
        // RELAY: a buyer asks this wallet to hold a parcel. Agreeing costs nothing; the bond is locked only when its
        // owner says the parcel arrived.
        "custody-request" => {
            if !RELAY_ON.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(None);
            }
            let request = part("request")?;
            if !is_bond(&request) {
                return Ok(None);
            }
            let title = text("title");
            let Ok(accept) = vault_ops::order_accept(&request, amount_of(&request), &title) else { return Ok(None) };
            locked(&PICKUPS).insert(id_of(&accept), (from.to_string(), title.clone()));
            send(from, "custody-accept", &serde_json::json!({ "accept": accept }))?;
            Ok(Some(format!("Pickup requested: {title}.")))
        }
        // BUYER: the relay agreed. Name its lock (no money moves) and tell the seller whose bond stands behind the parcel.
        "custody-accept" => {
            let accept = part("accept")?;
            let found = locked(&BUYING).iter().find(|(_, b)| b.relay.as_deref() == Some(from) && b.custody.as_ref().is_some_and(|(r, f)| id_of(r) == id_of(&accept) && f.is_none())).map(|(k, b)| (k.clone(), b.clone()));
            let Some((sale, b)) = found else { return Ok(None) };
            let funded = vault_ops::order_fund(&accept)?;
            let request = b.custody.as_ref().map(|(r, _)| r.clone()).unwrap_or_default();
            if let Some(entry) = locked(&BUYING).get_mut(&sale) {
                entry.custody = Some((request.clone(), Some(funded.clone())));
            }
            let title = title_in(word(&b.offer, "t"));
            send(from, "custody-lock", &serde_json::json!({ "title": title, "request": request, "funded": funded }))?;
            let _ = send(&b.seller, "custody", &serde_json::json!({ "offer": b.offer, "fields": vault_ops::bond_fields(&id_of(&request))? }));
            Ok(Some("Your pickup relay agreed to hold this order.".to_string()))
        }
        // RELAY: the buyer named this wallet's lock. The bond is ready to post when the parcel arrives.
        "custody-lock" | "custody-code" => {
            let (request, funded) = (part("request")?, part("funded")?);
            if !is_bond(&request) {
                return Ok(None);
            }
            let title = text("title");
            let st = vault_ops::order_funded(&request, &funded, &title)?;
            locked(&PICKUPS).insert(id_of(&st), (from.to_string(), title.clone()));
            if kind == "custody-lock" {
                return Ok(Some(format!("Pickup ready: {title}. Tap Parcel received when it arrives.")));
            }
            let code = text("code");
            if !vault_ops::order_code_is_good(&code).unwrap_or(false) {
                return Ok(Some(format!("A wrong pickup code arrived for {title}. Nothing was taken.")));
            }
            if st["locked"] == true {
                vault_ops::order_release(&code)?;
            }
            locked(&PICKUPS).remove(&id_of(&st));
            Ok(Some(format!("Picked up: {title}. Your custody bond is released.")))
        }
        // SELLER: a relay's custody bond stands behind this order's parcel. It is this wallet's at the deadline if the
        // parcel is never picked up. Watched only for this wallet's own offer and for at least its price.
        "custody" => {
            let (offer, fields) = (part("offer")?, part("fields")?);
            let Ok(t) = own_offer(&offer) else { return Ok(None) };
            if amount_of(&fields) < t.amount {
                return Ok(None);
            }
            let Ok(_) = vault_ops::bond_watch(&fields, &t.title) else { return Ok(None) };
            Ok(Some(format!("{}: pickup at a relay. Ship to the relay; its custody bond covers the parcel.", t.title)))
        }
        _ => Ok(None),
    }
}

/// One sale letter out of an opened message: `(kind, from, body, the letter's content hash)`.
fn sale_letter(m: &serde_json::Value) -> Option<(String, String, serde_json::Value, String)> {
    let (from, msg, cm) = (m.get("from")?.as_str()?, m.get("msg")?.as_str()?, m.get("cm")?.as_str()?);
    let (kind, body) = msg.strip_prefix(LETTER_HEAD)?.split_once(' ')?;
    Some((kind.to_string(), from.to_string(), serde_json::from_str::<serde_json::Value>(body).ok()?, cm.to_string()))
}

/// How many pages of the chain's letter columns one pass reads while catching up. It limits one call's work and
/// nothing else: what is left is read on the next pass, and every page is read.
// PRODUCTION-SCALE-REVIEWED: the same in production; a wallet closed for a year reads its year over more passes.
const HISTORY_PAGES_PER_PASS: u64 = 8;

/// Where this wallet's catch-up of the chain's letter columns stands: the next fold ordinal it has not read. A small
/// file beside the note store, named by the wallet's key and the chain like it. LOCAL-STORAGE-REQUIRED: without it a
/// reopened wallet would read every letter column from the chain's start on every open; with it lost, that is exactly
/// what it does once (a seed restore), so the file holds nothing a restore cannot rebuild. It names no letter, sender,
/// note or amount: one number, the chain position this device last read.
fn history_cursor_path() -> Option<std::path::PathBuf> {
    let ek = WALLET.lock().ok()?.as_ref()?.scan_ek.clone();
    let key = blake3::hash(&ek);
    let chain = crate::current_chain_id();
    let tail: String = chain.chars().rev().take(16).collect::<Vec<_>>().into_iter().rev().collect();
    Some(crate::node_data_dir().join(format!("sale-letters-{}-{tail}.cursor", hex::encode(&key.as_bytes()[..8]))))
}

/// BUYER of a download, after its wallet was CLOSED (audit F10, the part a wallet can close alone): a seller's key
/// letter that arrived meanwhile is no longer in the node's current letter slots (`/letter/inbox` holds the newest 64),
/// but every letter is anchored in a block and kept in the chain's letter columns (`/letter/history`, the pages a
/// restored wallet walks for its messages). So while this wallet holds a purchase a key could open (a buyer's order
/// with both lock slots filled, as a download's is), it reads those columns from where it last stopped to the tip, a
/// few pages a pass, and hands every KEY letter to the same handler the inbox feeds. Only key letters: that handler
/// was written for a wallet reopened since it paid (it checks the letter's lock against this wallet's own record of
/// the purchase, then the sealed content, then the key). Every other sale letter acts on what the session that sent
/// or awaited it still holds, and replaying one after a close would act twice or on nothing.
/// The pages are the same bytes for every asker and name no recipient, so the read tells the node only that this
/// wallet is reading letter history. With no such purchase open the cursor moves to the tip and nothing is read.
/// cons: one small local file (8 bytes); while a download is awaited, up to `HISTORY_PAGES_PER_PASS` page reads a pass
/// until the tip is reached, then at most one.
fn history_key_letters() -> Vec<(String, String, serde_json::Value, String)> {
    let Some(path) = history_cursor_path() else { return Vec::new() };
    let Some(top) = crate::probe_node(3_000).and_then(|i| i.get("served_seq").and_then(|b| b.as_u64())) else { return Vec::new() };
    let awaits_a_key = vault_ops::open_orders().iter().any(|o| o.role == "buyer" && !o.lock1.is_empty() && !o.lock2.is_empty());
    let stored = std::fs::read(&path).ok().and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok()).map(u64::from_le_bytes);
    let write = |at: u64| {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("cursor.tmp");
        if std::fs::write(&tmp, at.to_le_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    };
    if !awaits_a_key {
        // nothing a key letter could open: a purchase made later is read from here on (a cursor past a tip that moved
        // back, as after a chain reset, is brought back to it)
        if stored.map_or(true, |c| c != top) {
            write(top);
        }
        return Vec::new();
    }
    // no cursor: a new device restored from its words, which reads from the chain's start once
    let mut from = stored.unwrap_or(0).min(top);
    let mut letters = Vec::new();
    for _ in 0..HISTORY_PAGES_PER_PASS {
        if from >= top {
            break;
        }
        let Ok(page) = letter_history_impl(from) else { break };
        letters.extend(page.get("messages").and_then(|m| m.as_array()).into_iter().flatten().filter_map(sale_letter).filter(|(kind, ..)| kind == "key"));
        let width = page.get("page").and_then(|p| p.as_u64()).filter(|w| *w > 0).unwrap_or(64);
        // never past the tip: a column not folded yet is read when it is
        from = from.saturating_add(width).min(top);
    }
    if stored != Some(from) {
        write(from);
    }
    letters
}

/// Read this wallet's letters and act on every sale letter not yet acted on. Called while the Wallet or Merchant page
/// is open, and by the command line. Returns what happened, in words.
pub fn sync() -> Result<serde_json::Value, String> {
    let inbox = letter_inbox_impl()?;
    let opened: Vec<serde_json::Value> = inbox.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    // PAY BY NAME: whoever asked this wallet for an address to pay it at is answered here (`pay_name`)
    let named = crate::pay_name::answer_asks(&opened);
    let mut letters: Vec<(String, String, serde_json::Value, String)> = opened.iter().filter_map(sale_letter).collect();
    // F10: and the key letters that arrived while this wallet was closed (they are acted on once: the list below is by
    // content hash, and the same letter read from both places has one hash)
    letters.extend(history_key_letters());
    // this wallet's own "posting a bond" notes come first, whatever order the inbox lists them in
    letters.sort_by_key(|(kind, ..)| kind != "bondpost");
    let mut events = Vec::new();
    // WHY an order is not moving, in the words the step itself gave. A letter that cannot be acted on yet is looked at
    // again on the next pass; its reason used to be dropped, so a purchase stuck on one failing step said nothing for as
    // long as it was stuck (measured: 17 minutes on real nodes, 2026-11-10). The page shows these under the order.
    let mut waiting: Vec<String> = Vec::new();
    for (kind, from, v, cm) in letters {
        if !locked(&DONE).insert(cm.clone()) {
            continue;
        }
        match handle(&kind, &from, &v) {
            Ok(Some(line)) => events.push(line),
            Ok(None) => {}
            // "not now": look at this letter again on the next pass
            Err(why) => {
                locked(&DONE).remove(&cm);
                if !waiting.contains(&why) {
                    waiting.push(why);
                }
            }
        }
    }
    events.extend(named);
    events.extend(collect_started());
    events.extend(renew_started());
    events.extend(claim_due());
    events.extend(collect_keys());
    Ok(serde_json::json!({ "events": events, "waiting": waiting }))
}

/// BUYER: a download is over (its key arrived): its vaults are no longer waited on and its node stops watching.
fn finish_download(sale: &str) {
    let Some(b) = locked(&BUYING).remove(sale) else { return };
    let tags: Vec<String> = b.requests.iter().filter_map(|r| vault_ops::key_vault(&id_of(r)).ok()).map(|(_, tag)| hex::encode(tag)).collect();
    for r in &b.requests {
        vault_ops::key_done(&id_of(r));
    }
    if !tags.is_empty() {
        let _ = claim_watch(&[], &tags);
    }
}

fn claim_watch(watch: &[String], forget: &[String]) -> Result<serde_json::Value, String> {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .post(&format!("{}/claim_watch", node_url()))
        .send_json(serde_json::json!({ "spent_tags_hex": watch.join(","), "forget_hex": forget.join(",") }))
        .map_err(|e| format!("your node did not answer: {}", node_refusal(e)))?
        .into_json::<serde_json::Value>()
        .map_err(|e| format!("your node's answer could not be read: {e}"))
}

/// BUYER: for every download whose payment is locked, ask this wallet's own node for the tag laid beside each
/// vault's spent tag (the seller's delivery publishes the key there) and open the file with the key it carries.
fn collect_keys() -> Vec<String> {
    let waiting: Vec<(String, Buying)> = locked(&BUYING).iter().filter(|(_, b)| b.download.is_some() && b.fundeds.iter().all(Option::is_some)).map(|(k, b)| (k.clone(), b.clone())).collect();
    let mut said = Vec::new();
    for (sale, b) in waiting {
        let Some(checked) = &b.download else { continue };
        let vaults: Vec<(usdm_decider::whir_rec_block::VaultNote, [u8; 32])> = b.requests.iter().filter_map(|r| vault_ops::key_vault(&id_of(r)).ok()).collect();
        let watch: Vec<String> = vaults.iter().map(|(_, tag)| hex::encode(tag)).collect();
        let Ok(found) = claim_watch(&watch, &[]) else { continue };
        let key = found["found"].as_array().into_iter().flatten().find_map(|row| {
            let spent = hex::decode(row["spent_tag"].as_str()?).ok()?;
            let claim = hex::decode(row["claim_tag"].as_str()?).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).and_then(|b| usdmd_node::spend_frontier::cm_bytes_to_root(&b))?;
            let (vault, _) = vaults.iter().find(|(_, tag)| tag[..] == spent[..])?;
            // a tag that is not this vault's delivery claim, or whose key is not the lock's, is no key
            usdm_decider::whir_rec_block::delivered_secret(&claim, vault).filter(|k| digital::key_fits(checked, k))
        });
        let Some(key) = key else { continue };
        let title = title_in(word(&b.offer, "t"));
        match take_key(&sale, &title, checked, &key) {
            Ok(line) => {
                finish_download(&sale);
                said.push(line);
            }
            Err(e) => said.push(format!("{title}: {e}")),
        }
    }
    said
}

/// SELLER: tell the buyer of sale `id` the parcel's tracking number, so its wallet pins it before the parcel moves.
pub fn shipped(id: &str, tracking: &str) -> Result<serde_json::Value, String> {
    let tracking: String = tracking.chars().filter(char::is_ascii_alphanumeric).take(40).collect();
    if tracking.len() < 8 {
        return Err("enter the carrier's tracking number".to_string());
    }
    let buyer = locked(&BUYERS).get(id).cloned().ok_or_else(|| "this wallet was closed since that sale: ask the buyer to confirm receipt when it arrives".to_string())?;
    send(&buyer, "shipped", &serde_json::json!({ "sale": id, "tracking": tracking }))?;
    Ok(serde_json::json!({ "sent": true, "tracking": tracking }))
}

/// SELLER: prove the carrier's delivery notice `eml` (the saved email) for sale `id` and hand the proof to the buyer's
/// wallet, which checks it and confirms receipt by itself. The proof is stored on the Veil (the storage price is paid)
/// and the buyer is sent where it is.
pub fn delivered(id: &str, eml: &[u8]) -> Result<serde_json::Value, String> {
    let buyer = locked(&BUYERS).get(id).cloned().ok_or_else(|| "this wallet was closed since that sale: ask the buyer to confirm receipt".to_string())?;
    let read = notice::read_notice(eml)?;
    let (shown, proof) = notice::prove(&notice::carriers(), id, &read)?;
    let stored = veil_site::store(&proof)?;
    let root = stored["root"].as_str().unwrap_or("").to_string();
    send(&buyer, "delivered", &serde_json::json!({ "sale": id, "shown": shown, "proof": root }))?;
    Ok(serde_json::json!({ "sent": true, "proof_bytes": proof.len() }))
}

/// BUYER: the tracking numbers sellers have named and this wallet's owner has not accepted: `[{id, title, tracking}]`.
pub fn tracking_offers() -> serde_json::Value {
    let buying = locked(&BUYING);
    let rows: Vec<serde_json::Value> = locked(&PIN_OFFERS)
        .iter()
        .filter(|(sale, _)| !locked(&PINS).contains_key(*sale))
        .map(|(sale, tracking)| serde_json::json!({ "id": sale, "tracking": tracking, "title": buying.get(sale).map(|b| title_in(word(&b.offer, "t"))).unwrap_or_default() }))
        .collect();
    serde_json::json!({ "offers": rows })
}

/// BUYER: accept the tracking number the seller named for purchase `id`. THIS is the pin: from now on the carrier's
/// signed notice that this parcel was delivered, dated after this moment, confirms receipt and releases the payment.
/// It is the owner's act, taken after the wallet has said what it means; no letter can do it.
pub fn accept_tracking(id: &str) -> Result<serde_json::Value, String> {
    let seller = locked(&BUYING).get(id).map(|b| b.seller.clone()).ok_or_else(|| "this wallet was closed since that purchase: confirm receipt yourself when the parcel arrives".to_string())?;
    let tracking = locked(&PIN_OFFERS).get(id).cloned().ok_or_else(|| "the seller has not named a parcel for this purchase".to_string())?;
    if accepted_carriers().is_empty() {
        return Err("this version accepts no carrier's delivery notice: confirm receipt yourself when the parcel arrives".to_string());
    }
    let now = node_chain_time_ms() / 1000;
    if now == 0 {
        return Err("the node did not answer".to_string());
    }
    let pinned = locked(&PINS).entry(id.to_string()).or_insert((tracking, now)).clone();
    locked(&PIN_OFFERS).remove(id);
    send(&seller, "pinned", &serde_json::json!({ "sale": id, "tracking": pinned.0, "at": pinned.1 }))?;
    Ok(serde_json::json!({ "pinned": true, "tracking": pinned.0, "at": pinned.1 }))
}

/// The carriers whose delivery notices this build accepts as proof (none when the release confirmed no key).
pub fn accepted_carriers() -> Vec<String> {
    notice::carriers().into_iter().map(|c| c.name).collect()
}

/// BUYER: the downloads that arrived: `[{id, title, name, bytes, saved}]`, `saved` the path the file was written to
/// (null while the write has not succeeded).
pub fn downloads() -> serde_json::Value {
    let rows: Vec<serde_json::Value> = locked(&DOWNLOADS)
        .iter()
        .map(|(id, d)| serde_json::json!({ "id": id, "title": d.title, "name": d.name, "bytes": d.size, "saved": d.saved.as_ref().map(|p| p.display().to_string()) }))
        .collect();
    serde_json::json!({ "downloads": rows })
}

/// BUYER: write an arrived download whose first write failed (a full disk, a folder that was missing). Returns where
/// the file is.
pub fn download_save(id: &str) -> Result<serde_json::Value, String> {
    let (name, bytes) = {
        let all = locked(&DOWNLOADS);
        let d = all.get(id).ok_or_else(|| "that download is not on this device".to_string())?;
        if let Some(path) = &d.saved {
            return Ok(serde_json::json!({ "saved": path.display().to_string() }));
        }
        (d.name.clone(), d.bytes.clone())
    };
    let path = save_file(&name, &bytes)?;
    if let Some(d) = locked(&DOWNLOADS).get_mut(id) {
        d.saved = Some(path.clone());
        d.bytes = Vec::new();
    }
    Ok(serde_json::json!({ "saved": path.display().to_string() }))
}

/// BUYER: the owner has seen where the file is; its row leaves the list. A file not yet written stays.
pub fn download_saved(id: &str) {
    let mut all = locked(&DOWNLOADS);
    if all.get(id).is_some_and(|d| d.saved.is_some()) {
        all.remove(id);
    }
}

/// MERCHANT: every subscription payment whose period has started is collected, by the clock alone.
fn collect_started() -> Vec<String> {
    let mut said = Vec::new();
    for o in vault_ops::open_orders().into_iter().filter(|o| o.kind == "sub" && o.role == "seller" && o.state == "locked") {
        let Ok(st) = vault_ops::order_status(&o.id) else { continue };
        if st["locked"] == true && st["deadline_passed"] == true && vault_ops::order_collect(&o.id).is_ok() {
            said.push(format!("Collected: {} ${:.2}.", o.title, atomic_to_usdm(o.amount)));
        }
    }
    said
}

/// BENEFICIARY: a relay's custody bond whose deadline passed with no pickup is taken, by the clock alone.
fn claim_due() -> Vec<String> {
    let mut said = Vec::new();
    for o in vault_ops::open_orders().into_iter().filter(|o| o.kind == "bond" && o.role == "beneficiary" && o.state == "locked") {
        let Ok(st) = vault_ops::order_status(&o.id) else { continue };
        if st["locked"] == true && st["deadline_passed"] == true && vault_ops::order_reclaim(&o.id).is_ok() {
            said.push(format!("{}: not picked up. The relay's custody bond of ${:.2} is yours.", o.title, atomic_to_usdm(o.amount)));
        }
    }
    said
}

/// SUBSCRIBER: once the period that is paid for has started, the next period's payment is set aside (the same request,
/// one period later). Only while this wallet has stayed open since subscribing; a closed wallet renews nothing by
/// itself, and the subscription then ends with the period already paid.
fn renew_started() -> Vec<String> {
    let now = node_chain_time_ms();
    let due: Vec<(String, Buying)> = locked(&BUYING)
        .iter()
        .filter(|(_, b)| b.period != 0 && b.fundeds.iter().all(Option::is_some))
        .filter(|(_, b)| now != 0 && b.requests[0].get("t_h").and_then(|t| t.as_u64()).is_some_and(|t| t.saturating_mul(HOUR_MS) <= now))
        .map(|(k, b)| (k.clone(), b.clone()))
        .collect();
    let mut said = Vec::new();
    for (key, b) in due {
        let (Ok(amount), Some(started)) = (num(&b.offer, "a"), b.requests[0].get("t_h").and_then(|t| t.as_u64())) else { continue };
        let title = title_in(word(&b.offer, "t"));
        let next = started.saturating_mul(HOUR_MS).saturating_add(b.period.saturating_mul(HOUR_MS));
        let Ok(request) = vault_ops::order_request_kind(&title, amount, next, "sub") else { continue };
        if send(&b.seller, "request", &serde_json::json!({ "offer": b.offer, "requests": [request.clone()] })).is_err() {
            continue;
        }
        let mut all = locked(&BUYING);
        all.remove(&key);
        all.insert(id_of(&request), Buying { requests: vec![request], fundeds: vec![None], download: None, ..b });
        said.push(format!("Subscription renewed: the next payment for {title} is scheduled."));
    }
    said
}

/// SUBSCRIBER: stop a subscription. The payment set aside for a period that has not started comes back now; nothing
/// further is set aside.
pub fn cancel(id: &str) -> Result<serde_json::Value, String> {
    let key = locked(&BUYING).iter().find(|(_, b)| b.requests.iter().any(|r| id_of(r) == id)).map(|(k, _)| k.clone());
    if let Some(k) = key {
        locked(&BUYING).remove(&k);
    }
    match vault_ops::order_cancel(id) {
        Ok(_) => Ok(serde_json::json!({ "cancelled": true, "returned": true })),
        // the period it paid for has started: that payment is the merchant's; nothing more will be set aside
        Err(_) => Ok(serde_json::json!({ "cancelled": true, "returned": false })),
    }
}

/// SELLER: what each sale's deposit stands at: sale id → `{amount_atomic, received_atomic}`.
pub fn deposits() -> serde_json::Value {
    let all: Vec<(String, ([u8; 16], u64))> = locked(&DEPOSITS).iter().map(|(k, v)| (k.clone(), *v)).collect();
    let mut out = serde_json::Map::new();
    for (sale, (reference, amount)) in all {
        out.insert(sale, serde_json::json!({ "amount_atomic": amount, "received_atomic": deposit_received(&reference) }));
    }
    serde_json::Value::Object(out)
}

/// RELAY: the pickups this wallet agreed to hold, each with whether its bond is ready to post or already locked.
pub fn pickups() -> serde_json::Value {
    let all: Vec<(String, (String, String))> = locked(&PICKUPS).iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let rows: Vec<serde_json::Value> = all
        .into_iter()
        .filter_map(|(id, (_, title))| {
            let st = vault_ops::order_status(&id).ok()?;
            Some(serde_json::json!({
                "id": id, "title": title, "amount": st["amount"], "deadline_ms": st["deadline_ms"],
                "ready": st["state"] == "locked", "holding": st["locked"] == true || locked(&POSTED).contains(&id),
            }))
        })
        .collect();
    serde_json::json!({ "on": RELAY_ON.load(std::sync::atomic::Ordering::SeqCst), "pickups": rows })
}

/// RELAY: take pickups, or stop. Held in memory: a wallet that was just opened takes none.
pub fn relay_set(on: bool) {
    RELAY_ON.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// RELAY: the parcel for pickup `id` arrived. Locks the custody bond (the price) until the buyer picks it up.
pub fn parcel_received(id: &str) -> Result<serde_json::Value, String> {
    post_once(id)?;
    Ok(serde_json::json!({ "holding": true }))
}

#[tauri::command]
pub async fn sale_offer(
    title: String,
    amount_usdm: f64,
    hours: u64,
    period_hours: Option<u64>,
    deposit_usdm: Option<f64>,
    bond_usdm: Option<f64>,
    as_name: Option<String>,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let part = |v: Option<f64>| -> Result<u64, String> { v.filter(|x| *x > 0.0).map_or(Ok(0), usdm_to_atomic) };
        offer_terms(&title, usdm_to_atomic(amount_usdm)?, hours, period_hours.unwrap_or(0), part(deposit_usdm)?, part(bond_usdm)?, as_name.as_deref())
    })
    .await
    .map_err(|e| format!("sale_offer task failed: {e}"))?
}

/// SELLER: list a file as a download. `base64` is the file the page read.
#[tauri::command]
pub async fn sale_offer_download(title: String, amount_usdm: f64, hours: u64, name: String, base64: String, as_name: Option<String>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = veil_site::b64_decode(&base64).ok_or_else(|| "the file could not be read".to_string())?;
        let price = usdmd_node::veil::storage_price_atomic(bytes.len() as u64 + 400_000);
        require_user_approval(format!(
            "List {} as a download for ${amount_usdm:.2}. Its sealed copy is stored on the network for about ${:.2}, paid once",
            approval_short(&title, 60),
            atomic_to_usdm(price)
        ))?;
        offer_download(&title, usdm_to_atomic(amount_usdm)?, hours, &name, &bytes, as_name.as_deref())
    })
    .await
    .map_err(|e| format!("sale_offer_download task failed: {e}"))?
}

/// SELLER: the parcel's tracking number, for the buyer's wallet to pin.
#[tauri::command]
pub async fn sale_shipped(id: String, tracking: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || shipped(&id, &tracking)).await.map_err(|e| format!("sale_shipped task failed: {e}"))?
}

/// SELLER: the carrier's delivery notice (the saved email, as the page read it).
#[tauri::command]
pub async fn sale_delivered(id: String, base64: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let eml = veil_site::b64_decode(&base64).ok_or_else(|| "the email file could not be read".to_string())?;
        delivered(&id, &eml)
    })
    .await
    .map_err(|e| format!("sale_delivered task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_carriers() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "carriers": accepted_carriers() }))
}

/// BUYER: the tracking numbers sellers have named for this wallet's purchases, waiting for its owner.
#[tauri::command]
pub async fn sale_tracking_offers() -> Result<serde_json::Value, String> {
    Ok(tracking_offers())
}

/// BUYER: accept a seller's tracking number as the parcel whose delivery confirms receipt. Asked first, in plain words.
#[tauri::command]
pub async fn sale_accept_tracking(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let tracking = locked(&PIN_OFFERS).get(&id).cloned().unwrap_or_default();
        require_user_approval(format!(
            "Accept parcel {} as this order's delivery. When the carrier reports it delivered, your payment is released without asking you again. Accept only if the carrier's own page shows this parcel going to YOUR address: a seller could name another parcel",
            approval_short(&tracking, 40)
        ))?;
        accept_tracking(&id)
    })
    .await
    .map_err(|e| format!("sale_accept_tracking task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_downloads() -> Result<serde_json::Value, String> {
    Ok(downloads())
}

/// BUYER: write an arrived download whose first write did not succeed: `{saved: path}`.
#[tauri::command]
pub async fn sale_download(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || download_save(&id)).await.map_err(|e| format!("sale_download task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_download_saved(id: String) -> Result<serde_json::Value, String> {
    download_saved(&id);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub async fn sale_cancel(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Cancel this subscription".to_string())?;
        cancel(&id)
    })
    .await
    .map_err(|e| format!("sale_cancel task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_offers() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "offers": offers() }))
}

#[tauri::command]
pub async fn sale_groups() -> Result<serde_json::Value, String> {
    Ok(groups())
}

#[tauri::command]
pub async fn sale_read(link: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || read(&link)).await.map_err(|e| format!("sale_read task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_buy(link: String, relay: Option<String>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || buy(&link, relay.as_deref(), &require_user_approval)).await.map_err(|e| format!("sale_buy task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_i_have_it(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Confirm receipt — this releases your payment to the seller".to_string())?;
        i_have_it(&id)
    })
    .await
    .map_err(|e| format!("sale_i_have_it task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_call_off(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Cancel this sale and refund the buyer. A delivery bond you locked for it goes to the buyer at the deadline.".to_string())?;
        call_off(&id)
    })
    .await
    .map_err(|e| format!("sale_call_off task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_sync() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(sync).await.map_err(|e| format!("sale_sync task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_deposits() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(deposits).await.map_err(|e| format!("sale_deposits task failed: {e}"))
}

#[tauri::command]
pub async fn sale_pickups() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(pickups).await.map_err(|e| format!("sale_pickups task failed: {e}"))
}

/// RELAY: the switch. Turning it on asks first, in words that say what a pickup can cost.
#[tauri::command]
pub async fn sale_relay_set(on: bool) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if on && !RELAY_ON.load(std::sync::atomic::Ordering::SeqCst) {
            require_user_approval("Act as a pickup relay: buyers can ask you to hold their parcels. You lock a bond worth the parcel only when you confirm it arrived.".to_string())?;
        }
        RELAY_ON.store(on, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({ "on": on }))
    })
    .await
    .map_err(|e| format!("sale_relay_set task failed: {e}"))?
}

#[tauri::command]
pub async fn sale_parcel_received(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let amount = vault_ops::order_status(&id)?.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
        require_user_approval(format!(
            "Take custody of this parcel: ${:.2} of your money is locked as a bond until the buyer picks it up, and is lost if it is not picked up by the deadline",
            atomic_to_usdm(amount)
        ))?;
        parcel_received(&id)
    })
    .await
    .map_err(|e| format!("sale_parcel_received task failed: {e}"))?
}

// TWO-PARTY-REVIEWED: the tests below cover only what one wallet decides alone (how a link is read and written, and
// which requests match an offer's terms); a seller's wallet and a buyer's wallet as two processes on two nodes are the
// real-node check scratchpad/net/goods.py (its sale step drives `sale_offer`, `sale_buy`, `sale_sync` and `sale_have`
// through the wallet's command line).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sale_link_is_read_only_when_it_is_whole_and_plain() {
        let good = "monerousd:sale?s=@corner&a=42000000000&h=72&p=0&n=00aa11bb22cc33dd&k=0123456789abcdef0123456789abcdef&t=Road+bicycle";
        let monthly = read("monerousd:sale?s=@gym&a=999000000&h=0&p=720&n=00aa11bb22cc33dd&k=0123456789abcdef0123456789abcdef&t=Gym").expect("a subscription");
        assert_eq!(monthly["mode"], "subscription");
        assert!(monthly["sentence"].as_str().unwrap().contains("every month") && monthly["sentence"].as_str().unwrap().contains("$9.99"));
        let f = offer_fields(good).expect("a whole link");
        assert_eq!((num(&f, "a"), num(&f, "h"), word(&f, "s"), title_in(word(&f, "t"))), (Ok(42_000_000_000), Ok(72), "@corner", "Road bicycle".to_string()));
        let shown = read(good).expect("a readable offer");
        assert_eq!(shown["amount_atomic"], 42_000_000_000u64);
        assert!(shown["sentence"].as_str().unwrap().contains("$420.00") && shown["sentence"].as_str().unwrap().contains("3 days"));
        for bad in [
            "monerousd:pay?h=x&t=y",
            "monerousd:sale?s=@corner&a=42000000000&h=72&n=00aa&k=01",
            "monerousd:sale?s=@corner&a=forty&h=72&n=00aa&k=01&t=x",
            "monerousd:sale?s=@corner&a=1&h=72&n=00aa&k=01&t=x&z=1",
            "monerousd:sale?s=@cor ner&a=1&h=72&n=00aa&k=01&t=x",
            "monerousd:sale?s=@corner&a=1&h=72&n=00aa&k=01&t=<script>",
        ] {
            assert!(offer_fields(bad).is_err() || read(bad).is_err(), "{bad} was read as a sale");
        }
    }

    #[test]
    fn a_deposit_and_a_bond_are_said_before_the_tap_and_bad_terms_are_refused() {
        let with = "monerousd:sale?s=@corner&a=42000000000&h=72&p=0&n=00aa11bb22cc33dd&k=0123456789abcdef0123456789abcdef&t=Table&d=10000000000&b=2100000000";
        let shown = read(with).expect("a readable offer");
        let s = shown["sentence"].as_str().unwrap();
        assert!(s.contains("$100.00 of it is a deposit") && s.contains("$21.00 delivery bond"), "{s}");
        assert_eq!((shown["deposit_atomic"].as_u64(), shown["bond_atomic"].as_u64()), (Some(10_000_000_000), Some(2_100_000_000)));
        let t = |deposit: u64, bond: u64, period: u64| Terms { amount: 42_000_000_000, hours: if period == 0 { 72 } else { 0 }, period, deposit, bond, title: "Table".to_string(), dl: None };
        assert!(terms_ok(&t(0, 0, 0)).is_ok() && terms_ok(&t(10_000_000_000, 2_100_000_000, 0)).is_ok());
        assert!(terms_ok(&t(42_000_000_000, 0, 0)).is_err(), "a deposit of the whole price leaves nothing in escrow");
        assert!(terms_ok(&t(0, 42_000_000_001, 0)).is_err(), "a bond above the price");
        assert!(terms_ok(&t(1, 0, 720)).is_err() && terms_ok(&t(0, 1_000_000_000, 720)).is_err(), "a subscription has neither");
        // the requests a buyer sends must be the escrowed price in purchase parts and the bond in one bond part
        let terms = t(10_000_000_000, 2_100_000_000, 0);
        let price = |a: u64| serde_json::json!({ "amount": a, "of": "" });
        let bond = |a: u64| serde_json::json!({ "amount": a, "of": "bond" });
        assert!(requests_match(&terms, &[price(30_000_000_000), price(2_000_000_000), bond(2_100_000_000)]));
        assert!(!requests_match(&terms, &[price(42_000_000_000), bond(2_100_000_000)]), "the deposit is not escrowed twice");
        assert!(!requests_match(&terms, &[price(32_000_000_000)]), "the bond is missing");
        assert!(!requests_match(&terms, &[price(32_000_000_000), bond(1)]), "a smaller bond");
        assert!(!requests_match(&terms, &[price(32_000_000_000), bond(2_100_000_000), bond(2_100_000_000)]));
        assert!(!requests_match(&t(0, 0, 0), &[price(42_000_000_000), bond(1_000_000_000)]), "a bond nobody offered");
    }

    /// A SELLER NAMES A PARCEL, AND THAT NEVER PINS IT. The seller chooses the tracking number, so a wallet that pinned
    /// it on the seller's word would release the payment on the delivery of any parcel the seller cared to name. The
    /// letter makes at most an offer; only the owner's own acceptance pins, and a delivery letter with nothing pinned
    /// releases nothing.
    ///
    /// TWO-PARTY-REVIEWED: the subject is ONE side's own refusal rule: what the buyer's wallet does with a letter it is
    /// handed, whoever wrote it (the letter's bytes are the hostile input, and a hostile seller needs no wallet of ours
    /// to write them). Nothing here claims two wallets agree: a seller's wallet and a buyer's wallet crossing real
    /// nodes is `scratchpad/net/goods.py`.
    #[test]
    fn a_sellers_letter_never_pins_a_parcel() {
        let sale = "pin-pin-test-sale".to_string();
        let buying = Buying {
            seller: "@seller".to_string(),
            offer: serde_json::json!({ "t": "Lamp" }),
            requests: Vec::new(),
            fundeds: Vec::new(),
            period: 0,
            deposit_paid: false,
            relay: None,
            custody: None,
            download: None,
        };
        locked(&BUYING).insert(sale.clone(), buying);
        let said = handle("shipped", "@seller", &serde_json::json!({ "sale": sale, "tracking": "1Z999AA10123456784" }));
        assert!(said.is_ok(), "the letter is read without error: {said:?}");
        assert!(!locked(&PINS).contains_key(&sale), "⛔ a seller's letter pinned a parcel by itself");
        // with nothing pinned, a delivery letter releases nothing and says nothing
        let delivered = handle("delivered", "@seller", &serde_json::json!({ "sale": sale, "shown": {}, "proof": "00".repeat(32) }));
        assert_eq!(delivered, Ok(None), "⛔ a delivery letter was acted on for a parcel nobody accepted");
        // this build holds no carrier's key, so there is nothing to offer and nothing to accept
        if accepted_carriers().is_empty() {
            assert!(!locked(&PIN_OFFERS).contains_key(&sale), "no carrier is accepted, so no number is offered");
            assert!(accept_tracking(&sale).is_err(), "and none can be accepted");
        }
        assert!(!locked(&PINS).contains_key(&sale));
        locked(&BUYING).remove(&sale);
        locked(&PIN_OFFERS).remove(&sale);
    }

    /// A SELLER NAMES THE FILE, AND THE NAME IS NEVER A PATH: whatever the name says, the file lands inside the
    /// downloads folder, and a file already there is never written over.
    #[test]
    fn a_bought_file_is_written_inside_the_downloads_folder_and_never_over_another() {
        let folder = std::env::temp_dir().join(format!("musd-dl-{}-{:x}", std::process::id(), blake3::hash(b"a_bought_file").as_bytes()[0]));
        let _ = std::fs::remove_dir_all(&folder);
        let inside = |p: &std::path::Path| p.parent() == Some(folder.as_path());
        // what the test wrote, read back to assert it. O1-INFINITY-REVIEWED: a test's own check of one file it just wrote; no wallet or node state is rebuilt from it
        let written = |p: &std::path::Path| std::fs::read(p).expect("reads"); // O1-INFINITY-REVIEWED: test assertion of a just-written file, not state
        for hostile in ["../../escape.txt", "/etc/passwd", "..\\..\\boot.ini", ".zshrc", "..", "", "a\u{0}b\n.txt", "C:\\x:y?.txt"] {
            let path = save_file_in(&folder, hostile, b"paid for").expect("writes");
            assert!(inside(&path), "⛔ {hostile:?} left the downloads folder: {path:?}");
            let shown = path.file_name().expect("a name").to_string_lossy().to_string();
            assert!(!shown.starts_with('.') && !shown.contains(['/', '\\', ':', '\n', '\u{0}']), "⛔ {hostile:?} kept an unsafe name: {shown:?}");
            assert_eq!(written(&path), b"paid for");
        }
        // the same name twice: two files, the first untouched
        let first = save_file_in(&folder, "song.mp3", b"first").expect("writes");
        let second = save_file_in(&folder, "song.mp3", b"second").expect("writes");
        assert_ne!(first, second);
        assert_eq!(second.file_name().expect("a name").to_string_lossy(), "song (1).mp3");
        assert_eq!(written(&first), b"first", "⛔ a file already in the folder was written over");
        assert_eq!(written(&second), b"second");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_download_link_states_its_content_and_lock_and_nothing_else_rides_with_it() {
        let (x, l, c, v) = ("11".repeat(32), "22".repeat(32), "33".repeat(16), "44".repeat(32));
        let good = format!("monerousd:sale?s=@press&a=500000000&h=24&p=0&n=00aa11bb22cc33dd&k=0123456789abcdef0123456789abcdef&t=E-book&x={x}&l={l}&c={c}&v={v}");
        let t = terms_of(&offer_fields(&good).expect("a whole link")).expect("a download's terms");
        assert_eq!(t.dl, Some(digital::Listing { root: x.clone(), lock: l.clone(), salt: c.clone(), bundle: v.clone() }));
        let shown = read(&good).expect("a readable offer");
        assert_eq!(shown["mode"], "download");
        assert!(shown["sentence"].as_str().unwrap().contains("checks the file's proof before it asks you to pay"));
        // a download link missing a field, with a short field, or with a field that is not hex is refused
        for bad in [
            good.replace(&format!("&v={v}"), ""),
            good.replace(&format!("&c={c}"), "&c=3333"),
            good.replace(&format!("&x={x}"), &format!("&x={}", "zz".repeat(32))),
            // and it carries no deposit, bond or subscription, and leaves the seller time to deliver
            format!("{good}&d=100000000"),
            format!("{good}&b=100000000"),
            good.replace("&p=0", "&p=720"),
            good.replace("&h=24", "&h=1"),
        ] {
            assert!(offer_fields(&bad).and_then(|f| terms_of(&f)).is_err(), "{bad} was read as a download");
        }
        // the buyer's requests for a download are key requests under the listing's lock, and a purchase's never are
        let key = |a: u64, lock: &str| serde_json::json!({ "amount": a, "of": "key", "lock": lock });
        assert!(requests_match(&t, &[key(500_000_000, &l)]));
        assert!(requests_match(&t, &[key(300_000_000, &l), key(200_000_000, &l)]), "a price held in two parts under one lock");
        assert!(!requests_match(&t, &[key(500_000_000, &x)]), "another lock");
        assert!(!requests_match(&t, &[serde_json::json!({ "amount": 500_000_000u64, "of": "" })]), "an ordinary purchase request for a download");
        let plain = Terms { dl: None, ..t.clone() };
        assert!(!requests_match(&plain, &[key(500_000_000, &l)]), "a key request for an ordinary sale");
    }

    #[test]
    fn a_title_travels_as_plain_words() {
        assert_eq!(title_out("Road  bicycle, blue!"), "Road+bicycle,+blue");
        assert_eq!(title_in(&title_out("Road bicycle")), "Road bicycle");
        assert_eq!(title_out("<>&=?"), "Sale");
        assert_eq!(title_out(&"x".repeat(200)).len(), 60);
    }
}

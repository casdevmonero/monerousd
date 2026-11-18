// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ PUBLISHING A SITE ON MONEROUSD VEIL from the wallet (docs/VEIL-SOVEREIGN-INTERNET-SPEC-20261107.md §1, §7).
//! The Sovereign page's Publish pane (`dist/pages/sovereign.js`) reaches these through `veil_pack`, `veil_plan` and
//! `veil_publish`.
//!
//! PACK: the dropped files become ONE run of bytes, the same bytes on every machine (`usdmd_node::veil::pack_site`),
//! cut into chunks under one root, a chunk ending at every file boundary. UPDATE: a file that did not change is the
//! same chunks under the same hashes, so a new version hands over, stores and pays for only the files that changed
//! and the header ([`plan`] says which before the tap). PUBLISH: the wallet signs "site `name`, version `n`, root `r`" with the key that
//! owns the @name, hands the record to its own node, then hands over the index and each chunk. The node checks every
//! byte against the root before it keeps or passes anything on, so this wallet cannot publish bytes the root does not
//! name, and nobody else can publish under this name. READ BACK: what the node says the name's site is now.
//!
//! A site lives at a name the wallet already owns (`@flame` → `flame.mud`). Nothing is stored by the wallet: the bytes
//! go to the node's site store, the record to the chain's site registry.
//!
//! WHAT IT COSTS: the storage price ($0.50 per MB, once), paid by this wallet straight to the nodes that hold the
//! bytes, each its share, as ordinary private payments (`usdmd_node::veil_lane`, the payment). A holder keeps what it
//! was paid for until last; bytes nobody paid it for are only a reader's cache there. A holder whose operator named no
//! wallet is not paid and is told nothing. An update pays for its new bytes alone.
//!
//! BYTES WITH NO NAME ([`store`], [`read`]): a sale's sealed content is stored the same way under its root alone, and
//! read back by root through the wallet's own node, which fetches what it lacks privately.

use super::*;
use usdmd_node::veil::{pack_site, site_path_ok, storage_price_atomic, ChunkedSite, MUD_SUFFIX};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = u32::from(c[0]) << 16 | u32::from(*c.get(1).unwrap_or(&0)) << 8 | u32::from(*c.get(2).unwrap_or(&0));
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= c.len() { char::from(B64[(n >> shift & 63) as usize]) } else { '=' });
        }
    }
    out
}

pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for q in clean.chunks(4) {
        if q.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, b) in q.iter().enumerate() {
            n |= (B64.iter().position(|x| x == b)? as u32) << (18 - 6 * i as u32);
        }
        for i in 0..q.len() - 1 {
            out.push((n >> (16 - 8 * i as u32) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// The name a site address means: `flame`, `@flame` or `flame.mud` → `flame`.
fn site_name(domain: &str) -> Result<String, String> {
    let d = domain.trim().trim_start_matches('@').to_ascii_lowercase();
    let label = d.strip_suffix(MUD_SUFFIX).unwrap_or(&d);
    usdmd_node::veil::mud_name(&format!("{label}{MUD_SUFFIX}")).ok_or_else(|| "a site address is a name you own, like yourname.mud".to_string())
}

fn node_post(path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build()
        .post(&format!("{}{path}", node_url()))
        .send_json(body)
        .map_err(|e| format!("your node did not take it: {}", node_refusal(e)))?
        .into_json::<serde_json::Value>()
        .map_err(|e| format!("your node's answer could not be read: {e}"))
}

/// PACK the files the owner dropped. A folder dropped whole arrives as `folder/index.html`: when every path shares one
/// top folder it is taken off, so the site's front page is `index.html`. Returns what the screen shows and the packed
/// bytes it hands back to [`publish`].
pub fn pack(entries: &[(String, Vec<u8>)]) -> Result<serde_json::Value, String> {
    if entries.is_empty() {
        return Err("add at least one file".to_string());
    }
    let top = entries[0].0.split('/').next().unwrap_or("").to_string();
    let shared = !top.is_empty() && entries.iter().all(|(p, _)| p.split_once('/').is_some_and(|(first, rest)| first == top && !rest.is_empty()));
    let files: Vec<(String, Vec<u8>)> = entries
        .iter()
        .map(|(p, bytes)| (if shared { p[top.len() + 1..].to_string() } else { p.clone() }, bytes.clone()))
        .collect();
    if let Some((bad, _)) = files.iter().find(|(p, _)| !site_path_ok(p)) {
        return Err(format!("`{}` cannot be a page address: use letters, digits, dots, dashes and underscores", approval_short(bad, 60)));
    }
    if !files.iter().any(|(p, _)| p == "index.html") {
        return Err("a site needs an index.html: its front page".to_string());
    }
    let blob = pack_site(&files).ok_or_else(|| "these files could not be packed (a path is listed twice, or there are too many)".to_string())?;
    let site = ChunkedSite::of(&blob).ok_or_else(|| "there is nothing to publish".to_string())?;
    let price = storage_price_atomic(blob.len() as u64);
    Ok(serde_json::json!({
        "ok": true, "bundleBase64": b64_encode(&blob), "bundleSize": blob.len(), "rootHash": hex::encode(site.root().as_bytes()),
        "fileCount": files.len(), "chunks": site.chunks.len(), "storage_price_atomic": price, "storage_price_usdm": atomic_to_usdm(price),
        "feeAtomic": price.to_string(),
    }))
}

/// What this wallet's node says a name's site is now: `{ok, exists, rootHash, version}`.
pub fn site(domain: &str) -> Result<serde_json::Value, String> {
    let name = site_name(domain)?;
    let r = node_post("/veil/site", serde_json::json!({ "host": format!("{name}{MUD_SUFFIX}") }))?;
    let s = r.get("site").cloned().unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({
        "ok": true, "exists": !s.is_null(), "domain": format!("{name}{MUD_SUFFIX}"),
        "rootHash": s.get("root").cloned().unwrap_or_default(), "version": s.get("version").cloned().unwrap_or_default(),
    }))
}

/// The sites at the names THIS wallet owns, as its node has them: what the My Sites list shows.
pub fn my_sites() -> Result<serde_json::Value, String> {
    let handle = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.handle_address.clone()).ok_or_else(|| "no wallet open".to_string())?;
    let mine = node_post("/names_of", serde_json::json!({ "address": handle }))?;
    let names: Vec<String> = mine.get("names").and_then(|n| n.as_array()).map(|n| n.iter().filter_map(|x| x.as_str().map(|s| s.trim_start_matches('@').to_string())).collect()).unwrap_or_default();
    let mut sites = Vec::new();
    for name in names {
        let Ok(s) = site(&name) else { continue };
        if s["exists"] == true {
            sites.push(serde_json::json!({
                "domain": s["domain"], "version": s["version"].as_u64().map(|v| v.to_string()), "rootHash": s["rootHash"],
                "contentType": "static", "totalFeesAtomic": "0", "revoked": false,
            }));
        }
    }
    Ok(serde_json::json!({ "ok": true, "sites": sites }))
}

/// The index of the version `root_hex` names, as this wallet's own node holds it. `None` when it does not.
fn index_of(root_hex: &str) -> Option<ChunkedSite> {
    let r = node_post("/veil/index", serde_json::json!({ "root": root_hex })).ok()?;
    ChunkedSite::from_index(&hex::decode(r["index"].as_str()?).ok()?)
}

/// The files of a packed site, each as `(path, its length, its chunks' hashes)`.
fn files_of(blob: &[u8], site: &ChunkedSite) -> Option<Vec<(String, u64, Vec<usdmd_node::hash::Hash32>)>> {
    let header = blob.get(..usize::try_from(usdmd_node::veil::site_header_len(blob.get(..16)?)?).ok()?)?;
    let files = usdmd_node::veil::site_files(header, blob.len() as u64)?;
    let starts = site.starts();
    Some(
        files
            .into_iter()
            .map(|(path, start, len)| {
                let first = starts.partition_point(|s| *s < start);
                let last = starts.partition_point(|s| *s < start + len);
                (path, len, site.chunks.get(first..last).map(<[_]>::to_vec).unwrap_or_default())
            })
            .collect(),
    )
}

/// WHAT PUBLISHING `blob` AT `domain` WILL DO, before anything is signed or sent: the version it becomes, how many of
/// its bytes are new (stored and paid for) and how many the version before it already holds, which files changed,
/// and the price of the new bytes in dollars. An update that changes one file costs that file and the header.
pub fn plan(domain: &str, blob: &[u8]) -> Result<serde_json::Value, String> {
    let name = site_name(domain)?;
    let chunked = ChunkedSite::of(blob).ok_or_else(|| "there is nothing to publish".to_string())?;
    let files = files_of(blob, &chunked).ok_or_else(|| "drop the site's folder or files (an archive is not read as a site)".to_string())?;
    let now = site(&name)?;
    let before = now["rootHash"].as_str().filter(|r| !r.is_empty()).and_then(index_of);
    let had: std::collections::HashSet<usdmd_node::hash::Hash32> = before.iter().flat_map(|b| b.chunks.iter().copied()).collect();
    let new_bytes = usdmd_node::veil::new_bytes(before.as_ref(), &chunked);
    let changed: Vec<&str> = files.iter().filter(|(_, len, hashes)| *len > 0 && hashes.iter().any(|h| !had.contains(h))).map(|(p, ..)| p.as_str()).collect();
    let price = storage_price_atomic(new_bytes);
    Ok(serde_json::json!({
        "ok": true, "domain": format!("{name}{MUD_SUFFIX}"), "exists": now["exists"], "version": now["version"].as_u64().unwrap_or(0) + 1,
        "same": now["rootHash"].as_str() == Some(hex::encode(chunked.root().as_bytes()).as_str()),
        "bundleSize": blob.len(), "newBytes": new_bytes, "reusedBytes": (blob.len() as u64).saturating_sub(new_bytes),
        "fileCount": files.len(), "changedFiles": changed, "unchangedFiles": files.len() - changed.len(),
        "storage_price_atomic": price, "storage_price_usdm": atomic_to_usdm(price),
    }))
}

/// PUBLISH packed bytes as `domain`'s next version. `approve` is asked first, in words that say it cannot be undone.
pub fn publish(domain: &str, blob: &[u8], approve: &dyn Fn(String) -> Result<(), String>) -> Result<serde_json::Value, String> {
    let name = site_name(domain)?;
    // only bytes this wallet packed are published: an archive dropped whole is not a site a node can serve
    let header = usdmd_node::veil::site_header_len(blob.get(..16).unwrap_or(&[])).and_then(|n| blob.get(..usize::try_from(n).ok()?));
    if header.and_then(|h| usdmd_node::veil::site_files(h, blob.len() as u64)).is_none() {
        return Err("drop the site's folder or files (an archive is not read as a site)".to_string());
    }
    let chunked = ChunkedSite::of(blob).ok_or_else(|| "there is nothing to publish".to_string())?;
    let root = chunked.root();
    let (handle, spend_pk) = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.handle_address.clone(), w.spend_pk.clone())
    };
    // a site lives at a name THIS wallet owns: the node resolves name → owner key → that owner's publish
    let mine = node_post("/names_of", serde_json::json!({ "address": handle }))?;
    let owns = mine.get("names").and_then(|n| n.as_array()).is_some_and(|n| n.iter().any(|x| x.as_str().is_some_and(|x| x.trim_start_matches('@').eq_ignore_ascii_case(&name))));
    if !owns {
        return Err(format!("register @{name} in Settings first: a site lives at a name you own"));
    }
    let now = site(&name)?;
    if now["rootHash"].as_str() == Some(hex::encode(root.as_bytes()).as_str()) {
        return Err("these exact files are already published at this address".to_string());
    }
    let version = now["version"].as_u64().unwrap_or(0) + 1;
    // an update pays for its new bytes alone: the chunks the version before it does not already have
    let before = now["rootHash"].as_str().filter(|r| !r.is_empty()).and_then(index_of);
    let paid_len = usdmd_node::veil::new_bytes(before.as_ref(), &chunked);
    let price = storage_price_atomic(paid_len);
    let reused = (blob.len() as u64).saturating_sub(paid_len);
    approve(format!(
        "Publish {name}{MUD_SUFFIX} (version {version}: {} KB new{}) for ${:.2} storage, paid once to the nodes that hold it. A published site cannot be deleted from the network, only replaced by a new version",
        paid_len.div_ceil(1024),
        if reused > 0 && before.is_some() { format!(", {} KB kept from the version before", reused.div_ceil(1024)) } else { String::new() },
        atomic_to_usdm(price)
    ))?;
    let publish = usdmd_node::site::SitePublish::new(usdmd_node::pqauth::pubkey_id(&spend_pk), &name, version, root);
    let sig = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        pq::sign_spend(w, &usdmd_node::pqauth::site_publish_msg(&publish)).ok_or_else(|| "this wallet could not sign the publish".to_string())?
    };
    let root_hex = hex::encode(root.as_bytes());
    let said = node_post("/site/publish", serde_json::json!({ "name": name, "version": version, "root": root_hex, "pubkey": hex::encode(&spend_pk), "sig": hex::encode(&sig) }))?;
    match said.get("outcome").and_then(|o| o.as_str()) {
        Some("adopted") => {}
        Some("stale") => return Err("a newer version of this site is already published".to_string()),
        Some("wrong_owner") => return Err("this address belongs to another key".to_string()),
        _ => return Err("your node refused the publish".to_string()),
    }
    let put = |body: serde_json::Value| -> Result<(), String> {
        let r = node_post("/veil/put", body)?;
        if r.get("status").and_then(|s| s.as_str()) == Some("OK") {
            Ok(())
        } else {
            Err(format!("your node refused part of the site ({})", r.get("status").and_then(|s| s.as_str()).unwrap_or("no answer")))
        }
    };
    // the index first; the node answers with the chunks it does not hold, and only those are handed over (and passed
    // on): a file that did not change is already there under its hash, on this node and on every node that held the
    // version before
    let missing: Vec<u64> = {
        let r = node_post("/veil/put", serde_json::json!({ "root": root_hex, "index": hex::encode(chunked.index_bytes()) }))?;
        if r.get("status").and_then(|s| s.as_str()) != Some("OK") {
            return Err(format!("your node refused part of the site ({})", r.get("status").and_then(|s| s.as_str()).unwrap_or("no answer")));
        }
        match r.get("missing").and_then(|m| m.as_array()) {
            Some(list) => list.iter().filter_map(serde_json::Value::as_u64).collect(),
            None => (0..chunked.chunks.len() as u64).collect(),
        }
    };
    for i in &missing {
        let chunk = chunked.piece(blob, *i).ok_or_else(|| "the packed site is shorter than its index".to_string())?;
        put(serde_json::json!({ "root": root_hex, "i": i, "chunk": hex::encode(chunk) }))?;
    }
    // the holders are paid for the bytes this version adds. The site is published whether or not a payment goes
    // through: bytes a holder was not paid for are only a reader's cache there, and the screen says how many were paid.
    let paid = pay_storage(&root_hex, paid_len).unwrap_or_else(|e| serde_json::json!({ "paid": 0, "failed": e }));
    Ok(serde_json::json!({
        "ok": true, "domain": format!("{name}{MUD_SUFFIX}"), "version": version, "rootHash": root_hex, "tx_hash": root_hex, "chunks": chunked.chunks.len(),
        "chunksSent": missing.len(), "newBytes": paid_len, "reusedBytes": reused, "storage": paid,
    }))
}

fn random32() -> Result<[u8; 32], String> {
    use rand::RngCore as _;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut b).map_err(|_| "this device gave no randomness".to_string())?;
    Ok(b)
}

/// What storing `paid_len` bytes under `root` costs, and the holders that ask to be paid, as this wallet's node has
/// them after asking each: `{price_atomic, share_atomic, holders: [{id, spk, scan_ek}], waiting}`. Asks for a few
/// seconds; a holder that has not answered by then is not paid by this call.
pub fn storage_quote(root_hex: &str, paid_len: u64) -> Result<serde_json::Value, String> {
    let mut last = serde_json::Value::Null;
    for round in 0..15 {
        last = node_post("/veil/holders", serde_json::json!({ "root": root_hex, "total_len": paid_len }))?;
        let holders = last.get("holders").and_then(|h| h.as_array()).cloned().unwrap_or_default();
        if holders.iter().all(|h| h["answered"] == true) {
            break;
        }
        if round + 1 < 15 {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let holders = last.get("holders").and_then(|h| h.as_array()).cloned().unwrap_or_default();
    let payable: Vec<serde_json::Value> = holders.iter().filter(|h| h.get("spk").is_some()).cloned().collect();
    Ok(serde_json::json!({
        "price_atomic": last.get("price_atomic").cloned().unwrap_or_default(),
        "share_atomic": last.get("share_atomic").cloned().unwrap_or_default(),
        "holders": payable,
        "holders_known": holders.len(),
        "waiting": holders.iter().filter(|h| h["answered"] != true).count(),
    }))
}

/// PAY the holders of `root` for `paid_len` bytes, each its share, and tell each of its payment. Returns
/// `{paid, paid_atomic, holders, unpayable, failed}`. A payment that cannot be made stops the rest and is reported;
/// the holders already paid keep the bytes.
///
/// ⛔ AUDIT F11 (2026-11-10, measured on real nodes): a holder is paid ONLY at a receive address it names in its
/// terms (`address`: an ordinary address with a locator). A holder that names only bare keys is NOT paid: a note sealed
/// to bare keys is one its owner's wallet cannot spend or find again, so paying it would move the publisher's money
/// where nobody can use it. Today's nodes name no address, so today nothing is paid and the answer says so; the site
/// is published and held unpaid (an unpaid site gives up its place first when a holder runs out of room).
pub fn pay_storage(root_hex: &str, paid_len: u64) -> Result<serde_json::Value, String> {
    let quote = storage_quote(root_hex, paid_len)?;
    let share = quote["share_atomic"].as_u64().unwrap_or(0);
    let holders = quote["holders"].as_array().cloned().unwrap_or_default();
    let (mut paid, mut unpayable, mut failed) = (0u64, 0u64, None);
    for h in &holders {
        let Some(id) = h["id"].as_str() else { continue };
        let payable = h["address"].as_str().filter(|a| usdmd_node::address::parse_address_full(a).is_some_and(|p| p.locator.is_some() && p.spk.is_some()));
        let Some(to) = payable else {
            unpayable += 1;
            continue;
        };
        let secret = random32()?;
        let seed = node_post("/veil/pay_seed", serde_json::json!({ "root": root_hex, "total_len": paid_len, "holder": id, "secret": hex::encode(secret) }))?;
        let Some(seed) = seed["seed"].as_str().and_then(|x| hex::decode(x).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
            failed = Some("your node did not name the payment's seed".to_string());
            break;
        };
        if let Err(e) = wallet_send_atomic_seeded_blocking(to.to_string(), share, seed) {
            failed = Some(e);
            break;
        }
        // told after the payment is sent: a holder acts on the notice only once its own chain carries the payment
        let _ = node_post("/veil/paid", serde_json::json!({ "holder": id, "root": root_hex, "total_len": paid_len, "amount": share, "secret": hex::encode(secret) }));
        paid += 1;
    }
    if paid == 0 && failed.is_none() && quote["holders_known"].as_u64().unwrap_or(0) > 0 {
        failed = Some("Storage was not paid for: no holder named an address its wallet could find a payment at. Your site is published and held unpaid.".to_string());
    }
    Ok(serde_json::json!({
        "paid": paid, "paid_atomic": paid.saturating_mul(share), "paid_usdm": atomic_to_usdm(paid.saturating_mul(share)),
        "holders": holders.len(), "holders_known": quote["holders_known"], "unpayable": unpayable, "failed": failed,
    }))
}

/// STORE bytes under their root alone (a sale's sealed content): this wallet's own node keeps a copy, the holders are
/// paid, and each holder is handed the bytes once it has seen its payment. Returns `{root, len, paid, kept}`: `kept` is
/// how many holders said they keep the whole run. The wallet's own node always holds it.
pub fn store(blob: &[u8]) -> Result<serde_json::Value, String> {
    let site = ChunkedSite::of(blob).ok_or_else(|| "there is nothing to store".to_string())?;
    let root_hex = hex::encode(site.root().as_bytes());
    let items: Vec<(Option<usize>, Vec<u8>)> =
        std::iter::once((None, site.index_bytes())).chain(site.pieces(blob).enumerate().map(|(i, c)| (Some(i), c.to_vec()))).collect();
    let put = |item: &(Option<usize>, Vec<u8>)| -> Result<(u64, u64), String> {
        let body = match item.0 {
            None => serde_json::json!({ "root": root_hex, "bare": true, "index": hex::encode(&item.1) }),
            Some(i) => serde_json::json!({ "root": root_hex, "bare": true, "i": i, "chunk": hex::encode(&item.1) }),
        };
        let r = node_post("/veil/put", body)?;
        if r["status"] != "OK" {
            return Err(format!("your node refused part of it ({})", r["status"].as_str().unwrap_or("no answer")));
        }
        Ok((r["sent"].as_u64().unwrap_or(0), r["kept"].as_u64().unwrap_or(0)))
    };
    // this wallet's own node first: the bytes are held here whatever the holders do
    for item in &items {
        put(item)?;
    }
    let paid = pay_storage(&root_hex, blob.len() as u64)?;
    let want = paid["paid"].as_u64().unwrap_or(0);
    // each holder takes the bytes once its own chain shows its payment: hand them over until every paid holder says
    // it keeps every item, or the wait ends (the wallet's own node holds them either way and they can be handed again)
    let mut kept = 0u64;
    if want > 0 {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_secs(3));
            kept = items.iter().map(|item| put(item).map(|(_, k)| k)).collect::<Result<Vec<u64>, String>>()?.into_iter().min().unwrap_or(0);
            if kept >= want {
                break;
            }
        }
    }
    Ok(serde_json::json!({ "ok": true, "root": root_hex, "len": blob.len(), "paid": paid, "kept": kept }))
}

/// READ the bytes `root_hex` binds through this wallet's own node. What the node lacks it asks for privately; this
/// waits up to `wait_secs` for it to arrive.
pub fn read(root_hex: &str, wait_secs: u64) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut out: Vec<u8> = Vec::new();
    loop {
        let r = node_post("/veil/blob", serde_json::json!({ "root": root_hex, "from": out.len() }))?;
        match r["status"].as_str() {
            Some("OK") => {
                let piece = r["hex"].as_str().and_then(|h| hex::decode(h).ok()).ok_or_else(|| "your node's answer could not be read".to_string())?;
                let size = usize::try_from(r["size"].as_u64().unwrap_or(0)).unwrap_or(0);
                out.extend_from_slice(&piece);
                if out.len() >= size {
                    out.truncate(size);
                    return Ok(out);
                }
                if piece.is_empty() {
                    return Err("your node returned nothing for part of it".to_string());
                }
            }
            Some("NOT_HELD") => {
                if started.elapsed().as_secs() >= wait_secs {
                    return Err("it has not arrived on your node yet. Try again in a moment.".to_string());
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            other => return Err(format!("your node could not read it ({})", other.unwrap_or("no answer"))),
        }
    }
}

// ── BROWSING ON EVERY DEVICE: the wallet's own `veil:` scheme ───────────────────────────────────────────────────
//
// A `.mud` page was served only by the node's separate site host (the `serve-sites` process on 127.0.0.1:27752), which
// the desktop runs and a phone does not: on an iPhone a site could be found and never opened. The wallet core now
// serves Veil pages itself, on every platform, from its OWN node: `veil://localhost/mud/<name>/<path>` (macOS, iOS,
// Linux) or `http://veil.localhost/mud/<name>/<path>` (Windows, Android). Each file is read from the node's store,
// every byte already checked there against the root the chain anchors for that name, and served under the Veil's one
// policy (`usdmd_node::sovereign::veil_csp_at`, `veil_body`): sandboxed, nothing sent anywhere, code from the site's
// own path only, programs as text, the Back script in every page. Nothing leaves the machine but the node's private
// read of a site it does not hold yet. No capability names this scheme, so a page served on it reaches no wallet
// command (the wallet's bridge answers it only as its named site, `dist/app.js` `_veilSiteCall`).
//
// What protects it (AI RESISTANT, §2): (b) ordinary code and the engine's sandbox; the bytes themselves are (a),
// checked against the chain's root by the node before they are handed here.
// Scale: one loopback request per piece of at most 2 MiB; no state.

/// The addresses the wallet's `veil:` scheme is served at, on every platform.
pub const VEIL_SCHEME_BASES: [&str; 2] = ["veil://localhost", "http://veil.localhost"];

/// A response from the `veil:` scheme: status, headers, body.
pub type SchemeResponse = (u16, Vec<(String, String)>, Vec<u8>);

fn scheme_text(status: u16, html: &str) -> SchemeResponse {
    (status, vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string()), ("Cache-Control".to_string(), "no-store".to_string())], html.as_bytes().to_vec())
}

/// The percent-decoded path of a request, or `None` when it does not decode.
fn decode_path(p: &str) -> Option<String> {
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// SERVE one request of the `veil:` scheme. `path` is the request URI's path (`/mud/<name>/<file>`).
pub fn serve_scheme(path: &str) -> SchemeResponse {
    let Some(rest) = decode_path(path.split(['?', '#']).next().unwrap_or("")).and_then(|p| p.strip_prefix("/mud/").map(str::to_string)) else {
        return scheme_text(404, "<h1>404</h1><p>That is not a site address.</p>");
    };
    let (name, file) = rest.split_once('/').unwrap_or((rest.as_str(), ""));
    let file = if file.is_empty() || file.ends_with('/') { format!("{file}index.html") } else { file.to_string() };
    if usdmd_node::veil::mud_name(&format!("{name}{MUD_SUFFIX}")).as_deref() != Some(name) || !site_path_ok(&file) {
        return scheme_text(404, "<h1>404</h1><p>That is not a site address.</p>");
    }
    let body = match site_file(name, &file) {
        Err(_) => return scheme_text(503, "<p style=\"font:15px system-ui;padding:2rem\">This wallet's node did not answer.</p>"),
        Ok(SiteFile::Missing) => return scheme_text(404, "<h1>404</h1><p>No such page on this site.</p>"),
        Ok(SiteFile::NotHeld) => {
            return scheme_text(
                503,
                "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1\"><title>Fetching privately</title>\
<style>body{margin:0;height:100vh;display:grid;place-items:center;background:#0b0b0d;color:#c7c7cf;font:15px -apple-system,system-ui,sans-serif}\
i{display:block;width:34px;height:34px;margin:0 auto 14px;border-radius:50%;border:3px solid #26262e;border-top-color:#ff6a00;animation:s .8s linear infinite}\
@keyframes s{to{transform:rotate(360deg)}}</style><div><i></i>Fetching this site privately from the Veil…</div>",
            )
        }
        Ok(SiteFile::Bytes(b)) => b,
    };
    let (content_type, body) = usdmd_node::sovereign::veil_body(&file, body);
    let bases: Vec<String> = VEIL_SCHEME_BASES.iter().map(|b| (*b).to_string()).collect();
    let headers = vec![
        ("Content-Type".to_string(), content_type),
        ("Content-Security-Policy".to_string(), usdmd_node::sovereign::veil_csp_at(&bases, name)),
        ("Permissions-Policy".to_string(), usdmd_node::sovereign::VEIL_PERMISSIONS.to_string()),
        ("Referrer-Policy".to_string(), "no-referrer".to_string()),
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ("Cache-Control".to_string(), "no-cache".to_string()),
    ];
    (200, headers, body)
}

/// One file the Publish screen read: its path inside the dropped folder and its bytes in base64.
#[derive(serde::Deserialize)]
pub struct Entry {
    path: String,
    base64: String,
}

#[tauri::command]
pub async fn veil_pack(entries: Vec<Entry>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let files = entries.into_iter().map(|e| b64_decode(&e.base64).map(|b| (e.path, b))).collect::<Option<Vec<_>>>().ok_or_else(|| "a file could not be read".to_string())?;
        pack(&files)
    })
    .await
    .map_err(|e| format!("veil_pack task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_publish(domain: String, bundle_base64: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let blob = b64_decode(&bundle_base64).ok_or_else(|| "the packed site could not be read".to_string())?;
        publish(&domain, &blob, &require_user_approval)
    })
    .await
    .map_err(|e| format!("veil_publish task failed: {e}"))?
}

/// The default height class of a site's back end: 14 holds 33 slots, each text up to 768 bytes (37 KB a call).
pub const BACKEND_CLASS_DEFAULT: u64 = 14;

/// ASSEMBLE a back end's source (`usdm_decider::dsol_asm`): its bytecode, or the line that is wrong.
pub fn assemble(source: &str) -> Result<serde_json::Value, String> {
    if source.trim().is_empty() {
        return Ok(serde_json::json!({ "status": "EXAMPLE", "source": usdm_decider::dsol_asm::GUESTBOOK }));
    }
    let code = usdm_decider::dsol_asm::assemble(source)?;
    if code.len() > usdmd_node::dsol_deploy_tx::DSOL_CODE_BYTES_MAX {
        return Err(format!("the back end is {} bytes; the chain takes at most {}", code.len(), usdmd_node::dsol_deploy_tx::DSOL_CODE_BYTES_MAX));
    }
    let entries = usdm_decider::dsol_vm::parse_entries(&code).map(|e| e.len()).unwrap_or(0);
    Ok(serde_json::json!({
        "status": "OK",
        "code_hex": hex::encode(&code),
        "bytes": code.len(),
        "entries": entries,
        // what deploying it costs, shown in dollars before the person confirms
        "deploy_fee_atomic": usdmd_node::dsol_deploy_tx::dsol_deploy_fee_atomic(),
        "network_fee_atomic": P2P_FEE_ATOMIC,
        "slots": usdm_decider::dsol_blob_air::entries_for_class(BACKEND_CLASS_DEFAULT as u8),
        "text_bytes_max": usdm_decider::dsol_blob_air::STR_STORED_MAX,
    }))
}

/// DEPLOY a back end for site `name` (this wallet is its publisher): assemble, deploy, and hand back the two files the
/// site then carries — the bytecode at `backend.dsol` and `veil.json` binding it.
pub fn backend_deploy(name: &str, source: &str, publisher_fee_usdm: f64, height_class: u64) -> Result<serde_json::Value, String> {
    let code = usdm_decider::dsol_asm::assemble(source)?;
    let d = wallet_dsol_deploy_blocking(&hex::encode(&code), height_class, &format!("{name}{MUD_SUFFIX} back end"), publisher_fee_usdm)?;
    let veil_json = serde_json::json!({
        "backend": {
            "cid": d["cid"],
            "code": "backend.dsol",
            "view_ek": d["view_ek_hex"],
            "k_c": d["k_c_hex"],
            "manifest": d["manifest"],
        }
    });
    Ok(serde_json::json!({
        "status": "OK",
        "cid": d["cid"],
        "submitted": d["submitted"],
        "deploy_fee_atomic": d["deploy_fee_atomic"],
        "files": [
            { "path": "backend.dsol", "hex": hex::encode(&code) },
            { "path": "veil.json", "hex": hex::encode(serde_json::to_vec_pretty(&veil_json).unwrap_or_default()) },
        ],
    }))
}

#[tauri::command]
pub async fn veil_assemble(source: String) -> Result<serde_json::Value, String> {
    assemble(&source)
}

#[tauri::command]
pub async fn veil_backend_deploy(name: String, source: String, publisher_fee_usdm: f64, height_class: Option<u64>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || backend_deploy(&name, &source, publisher_fee_usdm, height_class.unwrap_or(BACKEND_CLASS_DEFAULT)))
        .await
        .map_err(|e| format!("veil_backend_deploy task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_backend_read(name: String, keys: serde_json::Value) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || backend_read(&name, &keys)).await.map_err(|e| format!("veil_backend_read task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_backend_price(name: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || backend_price(&name)).await.map_err(|e| format!("veil_backend_price task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_backend_call(name: String, entrypoint: String, argv_hex: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let argv = hex::decode(argv_hex.trim()).map_err(|_| "the call's argument is not hex".to_string())?;
        backend_call(&name, &entrypoint, &argv)
    })
    .await
    .map_err(|e| format!("veil_backend_call task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_backend_snapshot(name: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(match backend_snapshot(&name)? {
            Some((path, b)) => serde_json::json!({ "path": path, "hex": hex::encode(b) }),
            None => serde_json::Value::Null,
        })
    })
    .await
    .map_err(|e| format!("veil_backend_snapshot task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_seal(name: String, text: String) -> Result<String, String> {
    seal(&name, &text)
}

#[tauri::command]
pub async fn veil_open(name: String, sealed: String) -> Result<String, String> {
    open(&name, &sealed)
}

#[tauri::command]
pub async fn veil_plan(domain: String, bundle_base64: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let blob = b64_decode(&bundle_base64).ok_or_else(|| "the packed site could not be read".to_string())?;
        plan(&domain, &blob)
    })
    .await
    .map_err(|e| format!("veil_plan task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_my_sites() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(my_sites).await.map_err(|e| format!("veil_my_sites task failed: {e}"))?
}

#[tauri::command]
pub async fn veil_site(domain: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || site(&domain)).await.map_err(|e| format!("veil_site task failed: {e}"))?
}

// TWO-PARTY-REVIEWED: the tests below are what one wallet decides alone (how files are packed and named). A wallet
// publishing through one real node and another node's wallet browsing the site is a real-node check and is not
// claimed here.
// ── BACK ENDS: a site's own contract, read and called through the wallet (Veil spec §12) ──────────────────────────
//
// A `.mud` site binds a back end in a file of its own signed root, `veil.json`:
//   {"backend": {"cid": hex, "code": "<path of the bytecode in the site>", "view_ek": hex, "k_c": hex,
//                "manifest": {code_id, publisher_fee_atomic, publisher_spk, deployer_id, kc_commit, height_class}}}
// so only the name's owner can bind one, and a page reaches it only through the wallet's bridge, as its named site
// (`dist/app.js` `_veilSiteCall`): READS are answered from the back end's state as this wallet reads it from its own
// node (`dsol_replica`, checked against the chain's leaf); every WRITE is a call the person approves in dollars, paid
// and proven by this wallet (`dapp_provider_dsol_call_blocking`, whose fee is the chain's manifest, never the page's). A
// site reaches its OWN bound back end and nothing else.
//
// PRIVACY, three classes (spec §12): what a back end keeps is sealed under `k_c` (private from the chain and every node);
// `k_c` is in the site, so what the site's users share is readable by them; what is ONE PERSON'S is sealed by their own
// wallet before it is written (`seal` / `open`: a key of this wallet's seed and the site's name, so it opens on any device
// restored from the seed, and on no one else's).
// What protects it (AI RESISTANT): (a) every state read is the chain's own root; every call is proven; (b) the bridge's
// one-site rule. Nothing a page says can make the wallet pay without the person's confirmation in dollars.

/// A file of a site, read from this wallet's own node (every byte checked there against the root the chain anchors).
pub enum SiteFile {
    Bytes(Vec<u8>),
    /// the node does not hold the site yet (it is fetching it privately)
    NotHeld,
    /// the site has no such file
    Missing,
}

/// READ one file of a held site, piece by piece.
pub fn site_file(name: &str, file: &str) -> Result<SiteFile, String> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let r = node_post("/veil/file", serde_json::json!({ "host": format!("{name}{MUD_SUFFIX}"), "path": file, "from": body.len() }))?;
        match r["status"].as_str() {
            Some("OK") => {
                let piece = r["hex"].as_str().and_then(|h| hex::decode(h).ok()).unwrap_or_default();
                let size = usize::try_from(r["size"].as_u64().unwrap_or(0)).unwrap_or(0);
                let got = piece.len();
                body.extend_from_slice(&piece);
                if body.len() >= size || got == 0 {
                    body.truncate(size);
                    return Ok(SiteFile::Bytes(body));
                }
            }
            Some("NOT_HELD") => return Ok(SiteFile::NotHeld),
            _ => return Ok(SiteFile::Missing),
        }
    }
}

/// A site's bound back end.
pub struct Backend {
    pub cid: [u8; 32],
    pub k_c: [u8; 32],
    pub manifest_json: serde_json::Value,
    pub manifest: usdmd_node::dsol_deploy_tx::ContractManifest,
    pub view_ek: Vec<u8>,
    pub code: Vec<u8>,
    pub snapshot: Option<Vec<u8>>,
}

/// The path of a back end's sealed snapshot inside its site.
#[must_use]
pub fn snapshot_path(cid: &[u8; 32]) -> String {
    format!(".veil/state/{}", hex::encode(cid))
}

/// The back end `name` binds, from its own `veil.json`. `Err` says plainly when the site has none.
pub fn backend_of(name: &str) -> Result<Backend, String> {
    let site = format!("{name}{MUD_SUFFIX}");
    let json = match site_file(name, "veil.json")? {
        SiteFile::Bytes(b) => b,
        SiteFile::NotHeld => return Err(format!("{site} is still being fetched privately — try again in a moment")),
        SiteFile::Missing => return Err(format!("{site} has no back end")),
    };
    let v: serde_json::Value = serde_json::from_slice(&json).map_err(|_| format!("{site}'s veil.json is not readable"))?;
    let b = v.get("backend").ok_or_else(|| format!("{site} has no back end"))?;
    let h32 = |k: &str| b.get(k).and_then(|x| x.as_str()).and_then(hex32).ok_or_else(|| format!("{site}'s back end names no `{k}`"));
    let cid = h32("cid")?;
    let k_c = h32("k_c")?;
    let manifest_json = b.get("manifest").cloned().ok_or_else(|| format!("{site}'s back end names no manifest"))?;
    let manifest = dsol_manifest_of(&manifest_json)?;
    let view_ek = hex::decode(b.get("view_ek").and_then(|x| x.as_str()).unwrap_or("")).map_err(|_| format!("{site}'s back end view key is not hex"))?;
    let code_path = b.get("code").and_then(|x| x.as_str()).filter(|p| site_path_ok(p)).ok_or_else(|| format!("{site}'s back end names no code file"))?;
    let code = match site_file(name, code_path)? {
        SiteFile::Bytes(c) => c,
        _ => return Err(format!("{site}'s back end code `{code_path}` is not in the site")),
    };
    if *blake3::hash(&code).as_bytes() != manifest.code_id {
        return Err(format!("{site}'s back end code is not the contract's (its blake3 is not the manifest's code id)"));
    }
    let snapshot = match site_file(name, &snapshot_path(&cid))? {
        SiteFile::Bytes(s) => Some(s),
        _ => None,
    };
    Ok(Backend { cid, k_c, manifest_json, manifest, view_ek, code, snapshot })
}

/// The back end's state now, as this wallet reads it (checked against the chain's leaf).
fn backend_state(b: &Backend) -> Result<usdm_decider::dsol_vm::StorageTrie, String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let tree = dsol_tree_current(&agent)?;
    let leaf = tree.get(&b.cid).ok_or("this back end's contract is not on the chain this wallet's node follows")?;
    crate::dsol_replica::current(&agent, &b.cid, &b.k_c, &b.manifest, leaf, b.snapshot.as_deref())
}

/// The slot a page names: `"key"` (a plain key) or `{"map": "base", "key": "k"}` (a map entry), each a string the contract
/// used as its key.
fn slot_of(k: &serde_json::Value) -> Option<(String, usdm_decider::poseidon2_compress::Digest)> {
    use usdm_decider::dsol_vm::{map_slot, str_digest};
    if let Some(s) = k.as_str() {
        return Some((s.to_string(), str_digest(s.as_bytes())));
    }
    let (m, key) = (k.get("map")?.as_str()?, k.get("key")?.as_str()?);
    Some((format!("{m}[{key}]"), map_slot(&str_digest(m.as_bytes()), &str_digest(key.as_bytes()))))
}

/// READ a site's back end: the values of the slots the page names (at most 256), each a word, a text or nothing. Free.
pub fn backend_read(name: &str, keys: &serde_json::Value) -> Result<serde_json::Value, String> {
    let b = backend_of(name)?;
    let state = backend_state(&b)?;
    let mut out = serde_json::Map::new();
    for k in keys.as_array().map(Vec::as_slice).unwrap_or(&[]).iter().take(256) {
        let Some((label, slot)) = slot_of(k) else { continue };
        let v = match state.get(&slot) {
            Some(usdm_decider::dsol_vm::VmVal::Word(w)) => serde_json::json!({ "word": w }),
            Some(usdm_decider::dsol_vm::VmVal::Str { digest, .. }) => match state.contents.get(&digest) {
                Some(bytes) => match std::str::from_utf8(bytes) {
                    Ok(t) => serde_json::json!({ "text": t }),
                    Err(_) => serde_json::json!({ "hex": hex::encode(bytes) }),
                },
                None => serde_json::Value::Null,
            },
            None => serde_json::Value::Null,
        };
        out.insert(label, v);
    }
    Ok(serde_json::json!({ "status": "OK", "values": out, "publisher_fee_atomic": b.manifest.fee() }))
}

/// What a call to the site's back end costs the person, before they confirm: the publisher fee the CHAIN's manifest
/// holds (the wallet pays exactly that, `dapp_provider_dsol_call_blocking`).
pub fn backend_price(name: &str) -> Result<serde_json::Value, String> {
    let b = backend_of(name)?;
    Ok(serde_json::json!({ "status": "OK", "publisher_fee_atomic": b.manifest.fee(), "cid": hex::encode(b.cid) }))
}

/// CALL a site's back end: `entrypoint` with `argv`, paid and proven by this wallet. The page's confirmation sheet has
/// already shown the price in dollars.
pub fn backend_call(name: &str, entrypoint: &str, argv: &[u8]) -> Result<serde_json::Value, String> {
    let b = backend_of(name)?;
    let call = serde_json::json!({
        "cid": hex::encode(b.cid),
        "k_c": hex::encode(b.k_c),
        "manifest": b.manifest_json,
        "view_ek": hex::encode(&b.view_ek),
        "code": hex::encode(&b.code),
        "entrypoint": entrypoint,
        "argv": hex::encode(argv),
        "height_class": b.manifest.height_class,
        "snapshot": b.snapshot.as_deref().map(hex::encode).unwrap_or_default(),
    });
    dapp_provider_dsol_call_blocking(call)
}

/// The sealed snapshot of a site's back end as this wallet reads it now: what Publish puts at `.veil/state/<cid>` so a
/// reader whose node let the back end's newest state go still opens it. `None` when the site has no back end.
pub fn backend_snapshot(name: &str) -> Result<Option<(String, Vec<u8>)>, String> {
    let b = match backend_of(name) {
        Ok(b) => b,
        Err(e) if e.ends_with("has no back end") => return Ok(None),
        Err(e) => return Err(e),
    };
    let state = backend_state(&b)?;
    let mut salt = [0u8; 32];
    use rand::RngCore as _;
    rand::rngs::OsRng.try_fill_bytes(&mut salt).map_err(|_| "this device gave no randomness".to_string())?;
    let snap = crate::dsol_replica::snapshot_seal(&state, &usdm_decider::poseidon2_compress::hash32_to_digest(&b.k_c), salt)
        .ok_or("the back end's state could not be sealed")?;
    Ok(Some((snapshot_path(&b.cid), snap)))
}

/// The person's own key for a site: their seed's, under the site's name (any device restored from the seed derives it).
fn person_key(name: &str) -> Result<[u8; 32], String> {
    let root = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.dsol_root).ok_or_else(|| "no wallet open".to_string())?;
    let mut h = blake3::Hasher::new_keyed(&root);
    h.update(b"MonerousD/veil/person-seal/v1");
    h.update(name.as_bytes());
    Ok(*h.finalize().as_bytes())
}

/// The prefix of a person-sealed text.
pub const SEALED_PREFIX: &str = "mud1:";

fn seal_stream(key: &[u8; 32], nonce: &[u8; 16], data: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"stream");
    h.update(nonce);
    let mut xof = h.finalize_xof();
    let mut ks = vec![0u8; data.len()];
    xof.fill(&mut ks);
    for (d, k) in data.iter_mut().zip(ks) {
        *d ^= k;
    }
}

fn seal_tag(key: &[u8; 32], nonce: &[u8; 16], ct: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"tag");
    h.update(nonce);
    h.update(ct);
    h.finalize().as_bytes()[..16].try_into().expect("16 bytes")
}

/// SEAL a text to the person themselves, for `name`'s back end: `mud1:` + hex(nonce ‖ ciphertext ‖ tag). blake3 in
/// counter mode with a keyed blake3 tag (post-quantum: symmetric only, 256-bit key). Only this person's wallet opens it.
pub fn seal(name: &str, text: &str) -> Result<String, String> {
    seal_with(&person_key(name)?, text.as_bytes())
}

fn seal_with(key: &[u8; 32], text: &[u8]) -> Result<String, String> {
    let mut nonce = [0u8; 16];
    use rand::RngCore as _;
    rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| "this device gave no randomness".to_string())?;
    let mut ct = text.to_vec();
    seal_stream(key, &nonce, &mut ct);
    let tag = seal_tag(key, &nonce, &ct);
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(format!("{SEALED_PREFIX}{}", hex::encode(out)))
}

/// OPEN a text this person sealed for `name`. `Err` when it is not theirs, or was changed.
pub fn open(name: &str, sealed: &str) -> Result<String, String> {
    open_with(&person_key(name)?, sealed)
}

fn open_with(key: &[u8; 32], sealed: &str) -> Result<String, String> {
    let raw = sealed.strip_prefix(SEALED_PREFIX).and_then(|h| hex::decode(h).ok()).ok_or("that is not a sealed text")?;
    if raw.len() < 32 {
        return Err("that is not a sealed text".into());
    }
    let (nonce, rest) = raw.split_at(16);
    let (ct, tag) = rest.split_at(rest.len() - 16);
    let nonce: [u8; 16] = nonce.try_into().map_err(|_| "that is not a sealed text")?;
    if seal_tag(key, &nonce, ct) != tag {
        return Err("this text was not sealed by you for this site, or it was changed".into());
    }
    let mut pt = ct.to_vec();
    seal_stream(key, &nonce, &mut pt);
    String::from_utf8(pt).map_err(|_| "the sealed text is not text".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_length() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
            assert_eq!(b64_decode(&b64_encode(&bytes)), Some(bytes), "length {len}");
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_encode(b"Ma"), "TWE=");
        assert_eq!(b64_decode("TQ=="), Some(b"M".to_vec()));
        assert_eq!(b64_decode("T"), None);
        assert_eq!(b64_decode("T!=="), None);
    }

    #[test]
    fn a_dropped_folder_packs_to_the_same_root_however_it_is_dropped() {
        let page = |s: &str| s.as_bytes().to_vec();
        let flat = vec![("index.html".to_string(), page("<h1>hi</h1>")), ("css/site.css".to_string(), page("h1{color:red}"))];
        let in_folder: Vec<(String, Vec<u8>)> = flat.iter().rev().map(|(p, b)| (format!("my-site/{p}"), b.clone())).collect();
        let (a, b) = (pack(&flat).expect("packs"), pack(&in_folder).expect("packs"));
        assert_eq!(a["rootHash"], b["rootHash"], "the same files gave two roots");
        // a chunk ends at every file boundary: the header, then one chunk for each small file
        assert_eq!((a["fileCount"].as_u64(), a["chunks"].as_u64()), (Some(2), Some(3)));
        // the packed bytes come back as the same site
        let blob = b64_decode(a["bundleBase64"].as_str().unwrap()).expect("bytes");
        assert_eq!(hex::encode(ChunkedSite::of(&blob).unwrap().root().as_bytes()), a["rootHash"].as_str().unwrap());
        // one byte of one file changes the root
        let mut other = flat.clone();
        other[0].1[1] ^= 1;
        assert_ne!(pack(&other).expect("packs")["rootHash"], a["rootHash"]);
        // no front page, a path that climbs out, nothing at all: refused in words
        assert!(pack(&[("about.html".to_string(), page("x"))]).is_err());
        assert!(pack(&[("index.html".to_string(), page("x")), ("../secret".to_string(), page("y"))]).is_err());
        assert!(pack(&[]).is_err());
    }

    // TWO-PARTY-REVIEWED: this checks only the scheme's own refusal of what is not a site address, before any node is
    // asked. A page served by a wallet's scheme from bytes another node published is the real-node check veil.py.
    // TWO-PARTY-REVIEWED: a person's own sealing is one party by construction (only their seed opens it); a back end
    // written on one node and read on another is the real-node check backend.py.
    #[test]
    fn a_person_sealed_text_opens_only_with_their_key_for_that_site_and_never_once_changed() {
        let k = [3u8; 32];
        let s = seal_with(&k, b"my address: the hut by the river").unwrap();
        assert!(s.starts_with(SEALED_PREFIX));
        assert_eq!(open_with(&k, &s).unwrap(), "my address: the hut by the river");
        assert!(open_with(&[4u8; 32], &s).is_err(), "another person's key opened it");
        let mut raw = hex::decode(&s[SEALED_PREFIX.len()..]).unwrap();
        raw[20] ^= 1;
        assert!(open_with(&k, &format!("{SEALED_PREFIX}{}", hex::encode(raw))).is_err(), "a changed text opened");
        assert_ne!(seal_with(&k, b"same").unwrap(), seal_with(&k, b"same").unwrap(), "two seals of one text are told apart");
    }

    #[test]
    fn the_veil_scheme_refuses_what_is_not_a_site_address_before_asking_the_node() {
        for bad in ["/", "/apps/x", "/mud/", "/mud/Bad Name/", "/mud/flame/../secret", "/mud/flame/a//b", "/mud/flame/%zz", "/mud/a.b/"] {
            assert_eq!(serve_scheme(bad).0, 404, "{bad} was not refused");
        }
        assert_eq!(decode_path("/mud/flame/a%20b.html").as_deref(), Some("/mud/flame/a b.html"));
    }

    #[test]
    fn a_site_address_is_a_plain_name() {
        assert_eq!(site_name("flame.mud"), Ok("flame".to_string()));
        assert_eq!(site_name(" @Flame "), Ok("flame".to_string()));
        assert_eq!(site_name("flame"), Ok("flame".to_string()));
        assert!(site_name("flame.com").is_err() && site_name("a.b.mud").is_err() && site_name("").is_err());
    }
}

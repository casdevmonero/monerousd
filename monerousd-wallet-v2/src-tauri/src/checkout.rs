// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ goods spec §8 — PAYING A SHOP FROM A LINK. A shop's page shows one link, `monerousd:pay?h=<host>&t=<token>`; this
//! module is everything the wallet does with it: read the shop's offer, show the buyer one sentence, pay, and (for a
//! protected purchase) hand over the code when the buyer says the goods arrived.
//!
//! WHO THE WALLET TALKS TO. Only the shop's checkout helper, and only at a Tor v3 hidden address (through the wallet's
//! own embedded Tor, a fresh circuit per connection) or on this same machine. Any other host is refused here, before a
//! byte leaves: the buyer's network address never reaches a shop. The hidden address is self-authenticating, so the
//! link the shop showed is the proof of who answers.
//!
//! WHAT THE SHOP CAN DO TO THE BUYER: nothing beyond the price. A plain payment pays exactly the amount the shop SIGNED
//! (`verify_pos_charge`), which is the amount shown. A protected payment locks exactly the amount shown in a vault only
//! the buyer's own code releases; the shop's messages choose the seller's key and the refund lock, never the amount,
//! the deadline or who may take the money without the code.
//!
//! Nothing is stored. The link of a purchase made this session is kept in RAM so "I have it" is one tap; from a
//! restarted wallet the buyer copies the code to the shop instead, and the deadline returns the money either way.

use crate::{approval_short, atomic_to_usdm, require_user_approval, tor, vault_ops, verify_pos_charge, wallet_pos_pay_blocking};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// The shop link of each protected purchase made this session, by purchase id.
/// O1-FOOTPRINT-REVIEWED: RAM only, one short string per purchase of this session; nothing is written.
static LINKS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

const LINK_HEAD: &str = "monerousd:pay?";

/// A payment link the operating system handed this app before its page was listening (the app was opened BY the link).
/// O1-FOOTPRINT-REVIEWED: RAM only, one link; taken once by the page.
static OPENED: Mutex<Option<String>> = Mutex::new(None);

/// The operating system opened `link` with this app. Only a well-formed payment link is kept; the page shows the
/// shop's offer and nothing is paid without the buyer's own approval.
pub fn link_opened(link: &str) -> bool {
    // a shop's payment link, or a person's sale link
    let good = parse_link(link).is_ok() || crate::sale::read(link).is_ok();
    if good {
        *OPENED.lock().unwrap_or_else(|e| e.into_inner()) = Some(link.trim().to_string());
    }
    good
}

/// The page asks once, when it loads, for a link that opened the app.
#[tauri::command]
pub fn checkout_pending_link() -> Option<String> {
    OPENED.lock().unwrap_or_else(|e| e.into_inner()).take()
}

fn plain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

/// `(host, token)` of a shop link. The two fields are plain words by construction, so nothing is decoded.
pub fn parse_link(link: &str) -> Result<(String, String), String> {
    let query = link.trim().strip_prefix(LINK_HEAD).ok_or_else(|| "that is not a MonerousD payment link".to_string())?;
    let (mut host, mut token) = (None, None);
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("h", v)) if plain(v) => host = Some(v.to_string()),
            Some(("t", v)) if plain(v) && !v.contains(':') && !v.contains('.') => token = Some(v.to_string()),
            _ => return Err("the payment link is malformed".to_string()),
        }
    }
    match (host, token) {
        (Some(h), Some(t)) => Ok((h, t)),
        _ => Err("the payment link is incomplete".to_string()),
    }
}

/// The local base URL that reaches `host`: a hidden service through this wallet's own Tor, or a helper on this same
/// machine. Every other host is refused.
fn shop_base(host: &str) -> Result<String, String> {
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, Some(p.parse::<u16>().map_err(|_| "the payment link names a bad port".to_string())?)),
        None => (host, None),
    };
    if tor::is_onion_v3(name) {
        let local = tor::onion_forward(name, port.unwrap_or(80)).ok_or_else(|| "this wallet's private network could not start — nothing was sent".to_string())?;
        return Ok(format!("http://127.0.0.1:{local}"));
    }
    match (name, port) {
        ("127.0.0.1" | "localhost", Some(p)) => Ok(format!("http://127.0.0.1:{p}")),
        _ => Err("this shop's link does not use a hidden address, so paying it would show the shop where you are. Nothing was sent.".to_string()),
    }
}

fn agent() -> ureq::Agent {
    // a hidden service's first circuit can take tens of seconds
    ureq::AgentBuilder::new().timeout(Duration::from_secs(90)).build()
}

fn shop_error(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(_, resp) => resp
            .into_json::<serde_json::Value>()
            .ok()
            .and_then(|v| v.get("error").and_then(|x| x.as_str()).map(String::from))
            .map(|why| format!("the shop answered: {why}"))
            .unwrap_or_else(|| "the shop refused the request".to_string()),
        ureq::Error::Transport(_) => "the shop could not be reached".to_string(),
    }
}

fn shop_get(base: &str, token: &str, what: &str) -> Result<serde_json::Value, String> {
    agent().get(&format!("{base}/v1/pay/{token}/{what}")).call().map_err(shop_error)?.into_json().map_err(|_| "the shop's answer was not readable".to_string())
}

fn shop_post(base: &str, token: &str, what: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    agent().post(&format!("{base}/v1/pay/{token}/{what}")).send_json(body).map_err(shop_error)?.into_json().map_err(|_| "the shop's answer was not readable".to_string())
}

/// A price written as a decimal (`"12.50"`) as atomic units, exactly. `None` for anything else.
pub fn atomic_of_decimal(s: &str) -> Option<u64> {
    let (whole, frac) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    if whole.is_empty() || whole.len() > 11 || frac.len() > 8 || !whole.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut padded = frac.to_string();
    while padded.len() < 8 {
        padded.push('0');
    }
    whole.parse::<u64>().ok()?.checked_mul(100_000_000)?.checked_add(padded.parse::<u64>().ok()?).filter(|a| *a > 0)
}

fn words(v: &serde_json::Value, k: &str, n: usize) -> String {
    approval_short(v.get(k).and_then(|x| x.as_str()).unwrap_or(""), n)
}

/// What the shop offers, as the wallet will act on it: `{merchant, title, mode, amount_atomic, amount_usdm, deadline_ms,
/// status, sentence}`. For a plain payment the amount is the one the shop SIGNED, never the one it merely wrote.
pub fn offer(link: &str) -> Result<serde_json::Value, String> {
    let (host, token) = parse_link(link)?;
    read_offer(&shop_base(&host)?, &token).map(|(shown, _)| shown)
}

fn read_offer(base: &str, token: &str) -> Result<(serde_json::Value, serde_json::Value), String> {
    let raw = shop_get(base, token, "offer")?;
    let mode = raw.get("mode").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let merchant = words(&raw, "merchant", 40);
    let title = words(&raw, "title", 60);
    let status = raw.get("status").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let (amount, deadline_ms, sentence) = match mode.as_str() {
        "pay_now" => {
            let charge = raw.get("charge").ok_or_else(|| "the shop's offer has no charge".to_string())?;
            let (_, atomic) = verify_pos_charge(charge)?;
            (atomic, 0u64, format!("Pay ${:.2} to {merchant} for {title}. Final the moment it lands, like cash.", atomic_to_usdm(atomic)))
        }
        "protected" => {
            let atomic = raw.get("amount").and_then(|a| a.as_str()).and_then(atomic_of_decimal).ok_or_else(|| "the shop's offer names no price".to_string())?;
            let deadline_ms = raw.get("deadline_ms").and_then(|d| d.as_u64()).filter(|d| *d > 0).ok_or_else(|| "the shop's offer names no deadline".to_string())?;
            // THE SHOP CHOSE THE DEADLINE, and until it passes the buyer's money can leave escrow only by the buyer's
            // own code or the shop's refund. So it is said before the tap, in days, on the chain's clock: a shop that
            // names a date years away is asking to hold the money that long, and the buyer reads that here.
            let wait = crate::node_chain_time_ms();
            if wait == 0 {
                return Err("your node did not answer, so the refund date could not be read. Nothing was sent.".to_string());
            }
            if deadline_ms <= wait {
                return Err("this shop's offer has already ended. Nothing was sent.".to_string());
            }
            let hours = (deadline_ms - wait).div_ceil(3_600_000);
            let back = if hours == 1 {
                "one hour".to_string()
            } else if hours < 48 {
                format!("{hours} hours")
            } else {
                format!("{} days", hours.div_ceil(24))
            };
            let long = if hours > 24 * 30 { " That is a long time: your money stays locked until then unless you confirm receipt or the shop refunds it." } else { "" };
            (
                atomic,
                deadline_ms,
                format!(
                    "Pay ${:.2} to {merchant} for {title}. Held in escrow until you confirm receipt. If your order is not delivered, you can take your money back after {back}.{long}",
                    atomic_to_usdm(atomic)
                ),
            )
        }
        _ => return Err("the shop's offer is of a kind this wallet does not know".to_string()),
    };
    let shown = serde_json::json!({
        "merchant": merchant, "title": title, "mode": mode, "status": status,
        "amount_atomic": amount, "amount_usdm": atomic_to_usdm(amount), "deadline_ms": deadline_ms, "sentence": sentence,
    });
    Ok((shown, raw))
}

/// Pay the shop's offer. `approve` is asked the one sentence before anything is spent (the app's prompt; a headless
/// caller passes its own consent). A plain payment pays the signed charge; a protected one runs the whole handshake:
/// request, the shop's acceptance, the lock, the notice.
pub fn pay(link: &str, approve: &dyn Fn(String) -> Result<(), String>) -> Result<serde_json::Value, String> {
    let (host, token) = parse_link(link)?;
    let base = shop_base(&host)?;
    let (shown, raw) = read_offer(&base, &token)?;
    if !matches!(shown["status"].as_str(), Some("open" | "accepted")) {
        return Err("this order is no longer waiting for a payment — nothing was sent".to_string());
    }
    approve(shown["sentence"].as_str().unwrap_or("Pay this shop").to_string())?;
    let amount = shown["amount_atomic"].as_u64().ok_or_else(|| "the offer names no amount".to_string())?;
    if shown["mode"] == "pay_now" {
        let paid = wallet_pos_pay_blocking(raw.get("charge").cloned().ok_or_else(|| "the shop's offer has no charge".to_string())?)?;
        return Ok(serde_json::json!({ "paid": true, "mode": "pay_now", "amount_atomic": amount, "txid": paid.get("txid").cloned().unwrap_or_default() }));
    }
    let title = shown["title"].as_str().unwrap_or("order").to_string();
    let request = vault_ops::order_request(&title, amount, shown["deadline_ms"].as_u64().unwrap_or(0))?;
    let id = request["id"].as_str().unwrap_or("").to_string();
    let accept = shop_post(&base, &token, "request", serde_json::json!({ "request": request }))?
        .get("accept")
        .cloned()
        .ok_or_else(|| "the shop did not accept the purchase — nothing was sent".to_string())?;
    if accept.get("id").and_then(|i| i.as_str()) != Some(id.as_str()) {
        return Err("the shop answered for another purchase — nothing was sent".to_string());
    }
    let funded = vault_ops::order_fund(&accept)?;
    LINKS.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), link.trim().to_string());
    // the money is locked whether or not this notice arrives: it is the buyer's to take back at the deadline, and the
    // notice can be sent again
    let told = shop_post(&base, &token, "funded", serde_json::json!({ "funded": funded })).is_ok();
    Ok(serde_json::json!({ "paid": true, "mode": "protected", "id": id, "amount_atomic": amount, "shop_told": told, "funded": funded }))
}

fn link_of(id: &str) -> Result<String, String> {
    LINKS.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned().ok_or_else(|| {
        "this wallet no longer holds the shop's link for that purchase. Copy your code to the shop's order page instead.".to_string()
    })
}

/// "I have it": send the purchase's handover code to the shop, which takes its money with it.
pub fn hand_over(id: &str) -> Result<serde_json::Value, String> {
    let (host, token) = parse_link(&link_of(id)?)?;
    let code = vault_ops::order_code(id)?;
    let said = shop_post(&shop_base(&host)?, &token, "code", serde_json::json!({ "code": code }))?;
    Ok(serde_json::json!({ "handed_over": true, "status": said.get("status").cloned().unwrap_or_default() }))
}

/// Where the shop says the order stands. When the shop called the sale off it answers with its refund code, and the
/// money is taken back here at once.
pub fn status(id: &str) -> Result<serde_json::Value, String> {
    let (host, token) = parse_link(&link_of(id)?)?;
    let said = shop_get(&shop_base(&host)?, &token, "status")?;
    let mut out = serde_json::json!({ "status": said.get("status").cloned().unwrap_or_default(), "refunded": false });
    if let Some(code) = said.get("refund_code").and_then(|c| c.as_str()) {
        if code.starts_with(&format!("{id}:")) {
            out["refunded"] = serde_json::json!(vault_ops::order_refund(code).is_ok());
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn checkout_offer(link: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || offer(&link)).await.map_err(|e| format!("checkout_offer task failed: {e}"))?
}

#[tauri::command]
pub async fn checkout_pay(link: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || pay(&link, &require_user_approval)).await.map_err(|e| format!("checkout_pay task failed: {e}"))?
}

#[tauri::command]
pub async fn checkout_hand_over(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_user_approval("Confirm receipt — this releases your payment to the shop".to_string())?;
        hand_over(&id)
    })
    .await
    .map_err(|e| format!("checkout_hand_over task failed: {e}"))?
}

#[tauri::command]
pub async fn checkout_status(id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || status(&id)).await.map_err(|e| format!("checkout_status task failed: {e}"))?
}

// TWO-PARTY-REVIEWED: the three tests below cover only this wallet's own refusals (which links it reads, which hosts
// it dials, how it reads a price) and cross no boundary. The crossing itself (a buyer's wallet process paying a shop's
// helper process, whose own wallet on another node takes the money) is the real-node check `scratchpad/net/goods.py`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_is_read_only_when_it_is_exactly_a_payment_link() {
        let onion = format!("{}.onion", "b".repeat(56));
        assert_eq!(parse_link(&format!("monerousd:pay?h={onion}&t=Abc_123-x")).unwrap(), (onion.clone(), "Abc_123-x".to_string()));
        assert_eq!(parse_link("monerousd:pay?t=tok&h=127.0.0.1:8787").unwrap(), ("127.0.0.1:8787".to_string(), "tok".to_string()));
        for bad in [
            "https://shop.example/pay",
            "monerousd:pay?h=&t=tok",
            "monerousd:pay?h=shop.example",
            "monerousd:pay?h=a/b&t=tok",
            "monerousd:pay?h=shop.example&t=tok&x=1",
            "monerousd:pay?h=shop.example&t=../../orders",
        ] {
            assert!(parse_link(bad).is_err(), "{bad} was read as a payment link");
        }
    }

    #[test]
    fn no_host_but_a_hidden_address_or_this_machine_is_ever_dialled() {
        assert_eq!(shop_base("127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(shop_base("localhost:9").unwrap(), "http://127.0.0.1:9");
        for bad in ["shop.example", "shop.example:443", "10.0.0.7:8787", "127.0.0.1", "8.8.8.8:80", "localhost.evil.example:80"] {
            assert!(shop_base(bad).is_err(), "{bad} would have been dialled");
        }
    }

    #[test]
    fn a_price_is_read_exactly_or_not_at_all() {
        assert_eq!(atomic_of_decimal("12.5"), Some(1_250_000_000));
        assert_eq!(atomic_of_decimal("0.00000001"), Some(1));
        assert_eq!(atomic_of_decimal("7"), Some(700_000_000));
        for bad in ["", "0", "0.0", "-1", "1e3", "1.123456789", ".5", "1,5", "99999999999999999999"] {
            assert_eq!(atomic_of_decimal(bad), None, "{bad} was read as a price");
        }
    }
}

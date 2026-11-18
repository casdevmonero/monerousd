// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §21 / §21.1 — THE ONION PRICE RELAYS (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §21, §21.1).
//!
//! A validator quotes BTC and XMR with no human input: it asks onion price relays — the onion services Bisq's and Haveno's
//! own clients have read prices from for years (borrowed whole: their pricenode network, their response shapes) — over its
//! onion transport, and quotes the median only when ≥ 3 answers agree within 2 % AND at least two networks are among them. The
//! node is onion-only by cardinal; these are `.onion` services, so no clearnet exit is ever opened.
//!
//! THE RELAYS, read from each project's source on 2026-10-30 (never invented): Bisq's `PriceFeedNodeAddressProvider.java`
//! (operators @alexej996, @runbtc) and Haveno's `ProvidersRepository.java` (operators Haveno, Cake, Agorise), and on 2026-11-04 the
//! Haveno fork's list (boldsuck) and the mempool.space onions Bisq 2's own config reads (Bitcoin only) — the floor `list_is_diverse`
//! enforces on every release.
//!
//! ⛔ NO RELAY CAN HALT TRADING (user 2026-11-04: "trading must never be halted"). MEASURED 2026-11-04 over Tor: 3 of the 5 first relays answer, and one is the only live Bisq relay,
//! so a third network now carries Bitcoin. No loss of relays stops anything but a NEW mark: the sealed batch and the order book read no mark, a deposit is quoted at the standing mark and every door
//! values at the 7-day TWAP (`PegLedger::reference_price`), and no door reads a mark's age (`price_mark_tx`, the cardinal). A validator asks again each minute with a fresh draw while the chain holds no mark for the epoch.
//! Monero's price still rests on Bisq and Haveno, the only onion sources of it found: if either network were gone for good, no new XMR mark would form and the standing one would stay.
//!
//! THE COLLUSION DEFENSE (§21.1): two independent networks must agree; each validator samples by its own secret and the
//! epoch (a relay cannot aim a lie); outliers (> 2 %) and stale answers (> 2 epochs) are dropped; and a false mark must still
//! win > 2/3 of bond and then pass the TWAP / 30-day low / band every door reads (§19.6).
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: public market prices only; the request carries no user data and travels over onion.

use serde_json::Value;

/// `peg::ASSETS[1]` — the Monero peg's asset id.
pub const XMR_ASSET_ID: u32 = crate::peg::XMR_PEG_ASSET_ID;
/// An answer is fresh for two price epochs: 20 minutes, a TIME, never a count of blocks turned into one (finding A-F60's class:
/// this read `2 × PRICE_EPOCH_BLOCKS × 500`, true only at 500 ms blocks).
pub const FRESH_MS: u64 = 2 * crate::price_quote::PRICE_EPOCH_MS;
/// Answers more than this far from the median (basis points) are outliers.
pub const AGREE_BPS: u64 = 200;
/// The fewest agreeing answers a quote needs.
pub const MIN_AGREEING: usize = 3;
/// How many relays a validator asks per epoch.
pub const SAMPLE: usize = 6;

/// The relay network an answer came from (each has its own response shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Bisq,
    Haveno,
    /// mempool.space's own price API (Bitcoin only).
    Mempool,
}

/// One compiled relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    pub onion: &'static str,
    pub operator: &'static str,
    pub network: Network,
}

/// The relays this release reads (§21.1), each from its project's own source.
pub const RELAYS: &[Relay] = &[
    Relay { onion: "ro7nv73awqs3ga2qtqeqawrjpbxwarsazznszvr6whv7tes5ehffopid.onion", operator: "@alexej996", network: Network::Bisq },
    Relay { onion: "runbtcpn7gmbj5rgqeyfyvepqokrijem6rbw7o5wgqbguimuoxrmcdyd.onion", operator: "@runbtc", network: Network::Bisq },
    Relay { onion: "elaxlgigphpicy5q7pi5wkz2ko2vgjbq4576vic7febmx4xcxvk6deqd.onion", operator: "Haveno", network: Network::Haveno },
    Relay { onion: "lrrgpezvdrbpoqvkavzobmj7dr2otxc5x6wgktrw337bk6mxsvfp5yid.onion", operator: "Cake", network: Network::Haveno },
    Relay { onion: "agorise7ae5g7lkqp7r7qddsyzskft7cqhgguwkadbqamtsrap5onead.onion", operator: "Agorise", network: Network::Haveno },
    Relay { onion: "2c6y3sqmknakl3fkuwh4tjhxb2q5isr53dnfcqs33vt3y7elujc6tyad.onion", operator: "boldsuck", network: Network::Haveno },
    Relay { onion: "mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion", operator: "mempool.space", network: Network::Mempool },
    Relay { onion: "mempool4t6mypeemozyterviq3i5de4kpoua65r3qkn5i3kknu5l2cad.onion", operator: "emzy", network: Network::Mempool },
];

/// The path a network serves its prices at.
#[must_use]
pub fn path(network: Network) -> &'static str {
    match network {
        Network::Bisq | Network::Haveno => "/getAllMarketPrices",
        Network::Mempool => "/api/v1/prices",
    }
}

/// ⭐ THE BUILD CHECK: ≥ 5 relays from ≥ 4 operators across ≥ 2 networks.
#[must_use]
pub fn list_is_diverse(list: &[Relay]) -> bool {
    let mut ops: Vec<&str> = list.iter().map(|r| r.operator).collect();
    ops.sort_unstable();
    ops.dedup();
    let networks = [Network::Bisq, Network::Haveno].iter().filter(|n| list.iter().any(|r| r.network == **n)).count();
    list.len() >= 5 && ops.len() >= 4 && networks >= 2
}

/// One relay's answer as the recipient validator reads it: dollars per BTC and per XMR, and when the relay priced them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Answer {
    pub network: Network,
    pub usd_per_btc: f64,
    pub usd_per_xmr: f64,
    pub timestamp_ms: u64,
}

fn positive(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|p| p.is_finite() && *p > 0.0)
}

/// ⭐ Parse a relay's body in its network's own convention. `None` for anything malformed or missing a price.
#[must_use]
pub fn parse(network: Network, body: &[u8]) -> Option<Answer> {
    let v: Value = serde_json::from_slice(body).ok()?;
    // mempool.space: dollars per Bitcoin and a time in seconds; it prices nothing else, so its Monero figure is NaN and `quote` never reads it
    if network == Network::Mempool {
        let usd_per_btc = positive(v.get("USD"))?;
        let ts = v.get("time")?.as_u64()?;
        return Some(Answer { network, usd_per_btc, usd_per_xmr: f64::NAN, timestamp_ms: ts.saturating_mul(1000) });
    }
    let data = v.get("data")?.as_array()?;
    let (usd_per_btc, usd_per_xmr, timestamp_ms) = match network {
        Network::Mempool => return None, // answered above
        // Bisq: a fiat entry is fiat per BTC; a crypto entry is BTC per coin
        Network::Bisq => {
            let entry = |code: &str| data.iter().find(|e| e.get("currencyCode").and_then(Value::as_str) == Some(code));
            let (usd, xmr) = (entry("USD")?, entry("XMR")?);
            let usd_per_btc = positive(usd.get("price"))?;
            let btc_per_xmr = positive(xmr.get("price"))?;
            let ts = usd.get("timestampSec")?.as_u64()?.min(xmr.get("timestampSec")?.as_u64()?);
            (usd_per_btc, usd_per_btc * btc_per_xmr, ts.saturating_mul(1000))
        }
        // Haveno: counter per base, inverted to XMR as the base when it is not
        Network::Haveno => {
            let (mut usd_per_xmr, mut btc_per_xmr, mut ts) = (None, None, u64::MAX);
            for e in data {
                let (Some(base), Some(counter), Some(price)) = (
                    e.get("baseCurrencyCode").and_then(Value::as_str),
                    e.get("counterCurrencyCode").and_then(Value::as_str),
                    positive(e.get("price")),
                ) else {
                    continue;
                };
                let (counter, price) = if base.eq_ignore_ascii_case("XMR") { (counter, price) } else { (base, 1.0 / price) };
                let at = e.get("timestampMs").and_then(|t| t.as_u64().or_else(|| t.as_f64().map(|f| f as u64)));
                match counter {
                    "USD" => usd_per_xmr = Some(price),
                    "BTC" => btc_per_xmr = Some(price),
                    _ => continue,
                }
                ts = ts.min(at?);
            }
            let (usd_per_xmr, btc_per_xmr) = (usd_per_xmr?, btc_per_xmr?);
            (usd_per_xmr / btc_per_xmr, usd_per_xmr, ts)
        }
    };
    (usd_per_btc.is_finite() && usd_per_xmr.is_finite()).then_some(Answer { network, usd_per_btc, usd_per_xmr, timestamp_ms })
}

/// The lower median of a non-empty slice.
fn median(sorted: &[f64]) -> f64 {
    sorted[(sorted.len() - 1) / 2]
}

/// ⭐ THE QUOTE for `asset_id` (BTC = 0, XMR = 1) in the mark's units — USDm-atomic per external atomic unit × 10⁶ — from the
/// answers a validator gathered: fresh answers only; those within 2 % of the median agree; a quote only from ≥ 3 agreeing
/// answers that span at least TWO networks; then the median of the agreeing answers. `None` otherwise (the validator quotes
/// nothing until an ask answers). A network that does not price the asset gives no answer for it.
#[must_use]
pub fn quote(asset_id: u32, answers: &[Answer], now_ms: u64) -> Option<u128> {
    let scale = match asset_id {
        crate::peg::NATIVE_PEG_ASSET_ID => 1_000_000.0,
        XMR_ASSET_ID => 100.0,
        _ => return None,
    };
    let fresh: Vec<(Network, f64)> = answers
        .iter()
        .filter(|a| now_ms.saturating_sub(a.timestamp_ms) <= FRESH_MS)
        .map(|a| (a.network, if asset_id == XMR_ASSET_ID { a.usd_per_xmr } else { a.usd_per_btc } * scale))
        .filter(|(_, v)| v.is_finite())
        .collect();
    if fresh.len() < MIN_AGREEING {
        return None;
    }
    let mut all: Vec<f64> = fresh.iter().map(|x| x.1).collect();
    all.sort_by(f64::total_cmp);
    let m = median(&all);
    let agreeing: Vec<(Network, f64)> =
        fresh.into_iter().filter(|(_, v)| (v - m).abs() * 10_000.0 <= m * AGREE_BPS as f64).collect();
    let networks = [Network::Bisq, Network::Haveno, Network::Mempool].iter().filter(|n| agreeing.iter().any(|(x, _)| x == *n)).count();
    if agreeing.len() < MIN_AGREEING || networks < 2 {
        return None;
    }
    let mut vals: Vec<f64> = agreeing.iter().map(|x| x.1).collect();
    vals.sort_by(f64::total_cmp);
    let q = median(&vals).round();
    (q >= 1.0 && q < u128::MAX as f64).then(|| q as u128)
}

/// ⭐ The `k` relays (indices into [`RELAYS`]) this validator asks in `epoch`: the k lowest `H(secret ‖ epoch ‖ i)` — distinct,
/// deterministic for one validator and epoch, unpredictable to a relay.
#[must_use]
pub fn sample(secret: &[u8; 32], epoch: u64, k: usize) -> Vec<usize> {
    let mut scored: Vec<([u8; 32], usize)> = (0..RELAYS.len())
        .map(|i| {
            let mut h = blake3::Hasher::new_keyed(secret);
            h.update(b"MUSD/price-relay/sample/v1");
            h.update(&epoch.to_le_bytes());
            h.update(&(i as u64).to_le_bytes());
            (*h.finalize().as_bytes(), i)
        })
        .collect();
    scored.sort_unstable();
    scored.into_iter().take(k.min(RELAYS.len())).map(|(_, i)| i).collect()
}

/// The most response bytes read from one relay. Both networks' full price list is tens of KB; a relay sending more is
/// cut off and its answer dropped — what bounds the work a hostile relay can cause (charter §9.6 q5).
pub const MAX_RESPONSE: usize = 256 * 1024;

/// A relay's body read to its end — `None` past [`MAX_RESPONSE`] (the bound on a hostile relay's work).
#[must_use]
pub fn read_bounded(r: impl std::io::Read) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut body = Vec::new();
    r.take(MAX_RESPONSE as u64 + 1).read_to_end(&mut body).ok()?;
    (body.len() <= MAX_RESPONSE).then_some(body)
}

/// ⭐ §21 runtime — ASK ONE RELAY over the node's own Tor: the bridge watcher's onion-only agent (`btc_watch::agent`, the
/// SOCKS the node's Tor supervisor keeps up), `GET http://<onion>/getAllMarketPrices`, the body read bounded and parsed in
/// the relay's network's convention. `None` with no Tor route (never a direct path) or on any failure — the validator then
/// quotes from the relays that did answer, or not at all. Blocking: the runtime calls it off its tick thread.
/// DIGITAL-CASH-PRIVACY-REVIEWED: public market prices only; the request carries no user data and ends at an onion service.
#[must_use]
pub fn fetch(relay: &Relay) -> Option<Answer> {
    let agent = crate::btc_watch::agent()?;
    let resp = agent.get(&format!("http://{}{}", relay.onion, path(relay.network))).call().ok()?;
    parse(relay.network, &read_bounded(resp.into_reader())?)
}

/// One text answer from a Bitcoin explorer onion (`Network::Mempool`), retried while a fresh Tor builds its first circuits
/// (eight tries, five seconds apart), read bounded. `None` on every failure.
fn explorer_text(socks: &str, onion: &str, path: &str) -> Option<String> {
    for attempt in 0..8u32 {
        // A SOCKS username per attempt: Tor's IsolateSOCKSAuth (on by default) gives each its own circuit, so a retry never
        // rides the rendezvous circuit that just timed out (measured 2026-11-12: one explorer of two timed out three times in
        // a row on one circuit while the other answered in 5 s, and the next probe the reverse).
        let Ok(proxy) = ureq::Proxy::new(format!("socks5://anchor{attempt}:x@{socks}")) else { return None };
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(45)).proxy(proxy).build();
        if let Ok(resp) = agent.get(&format!("http://{onion}{path}")).call() {
            if let Some(body) = read_bounded(resp.into_reader()) {
                if let Ok(s) = String::from_utf8(body) {
                    return Some(s.trim().to_string());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    None
}

/// ⭐ A Bitcoin explorer's tip height (`GET /api/blocks/tip/height`), over the Tor SOCKS port `socks` (a fresh circuit per attempt) — read by
/// `usdmd-node launch-anchor` (params::LaunchAnchor) from EVERY `Network::Mempool` relay, which must agree.
/// DIGITAL-CASH-PRIVACY-REVIEWED: public Bitcoin chain data; the request carries nothing about anyone.
#[must_use]
pub fn explorer_tip_height(socks: &str, onion: &str) -> Option<u64> {
    explorer_text(socks, onion, "/api/blocks/tip/height")?.parse().ok()
}

/// ⭐ The hash of the Bitcoin block at `height` (`GET /api/block-height/<height>`), in the byte order explorers display it.
/// `None` unless the answer is exactly 64 hex digits.
/// DIGITAL-CASH-PRIVACY-REVIEWED: public Bitcoin chain data; the request carries nothing about anyone.
#[must_use]
pub fn explorer_block_hash(socks: &str, onion: &str, height: u64) -> Option<[u8; 32]> {
    let path = format!("/api/block-height/{height}");
    let text = explorer_text(socks, onion, &path)?;
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The sampling secret of the validator signing with `sk`: a one-way derivation, so the relays it asks say nothing of the key.
#[must_use]
pub fn sampler_secret(sk: &[u8]) -> [u8; 32] {
    blake3::derive_key("MUSD/price-relay/sampler/v1", sk)
}

/// What a simulated relay SERVES: the body relay `i` of [`RELAYS`] returns at `now_ms`, in its own network's shape (Bisq: USD
/// per BTC and BTC per XMR, seconds; Haveno: USD per XMR and XMR per BTC, milliseconds) — the bytes `parse` reads in
/// production, so the simulator's validators go through the same reader.
#[cfg(test)]
#[must_use]
pub fn sim_body(i: usize, usd_per_btc: f64, usd_per_xmr: f64, now_ms: u64) -> Vec<u8> {
    let btc_per_xmr = usd_per_xmr / usd_per_btc;
    match RELAYS[i % RELAYS.len()].network {
        Network::Mempool => format!(r#"{{"time":{},"USD":{usd_per_btc}}}"#, now_ms / 1000),
        Network::Bisq => format!(
            r#"{{"data":[{{"currencyCode":"USD","price":{usd_per_btc},"timestampSec":{},"provider":"sim"}},{{"currencyCode":"XMR","price":{btc_per_xmr},"timestampSec":{},"provider":"sim"}}],"bitcoinFeesTs":0}}"#,
            now_ms / 1000,
            now_ms / 1000
        ),
        Network::Haveno => format!(
            r#"{{"data":[{{"baseCurrencyCode":"XMR","counterCurrencyCode":"USD","price":{usd_per_xmr},"timestampMs":{now_ms}}},{{"baseCurrencyCode":"BTC","counterCurrencyCode":"XMR","price":{},"timestampMs":{now_ms}}}]}}"#,
            1.0 / btc_per_xmr
        ),
    }
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_730_250_000_000;

    /// The bytes a Bisq pricenode SENDS (the relay's side of the crossing), shaped as Bisq's own client parses them.
    fn bisq(usd_per_btc: f64, btc_per_xmr: f64, ts_sec: u64) -> Vec<u8> {
        format!(
            r#"{{"data":[{{"currencyCode":"USD","price":{usd_per_btc},"timestampSec":{ts_sec},"provider":"x"}},{{"currencyCode":"XMR","price":{btc_per_xmr},"timestampSec":{ts_sec},"provider":"y"}}],"bitcoinFeesTs":0}}"#
        )
        .into_bytes()
    }

    /// The bytes a Haveno price node SENDS, shaped as Haveno's own client parses them (an entry whose base is not XMR is
    /// inverted by the reader).
    fn haveno(usd_per_xmr: f64, btc_per_xmr: f64, ts_ms: u64) -> Vec<u8> {
        format!(
            r#"{{"data":[{{"baseCurrencyCode":"XMR","counterCurrencyCode":"USD","price":{usd_per_xmr},"timestampMs":{ts_ms}}},{{"baseCurrencyCode":"BTC","counterCurrencyCode":"XMR","price":{},"timestampMs":{ts_ms}}}]}}"#,
            1.0 / btc_per_xmr
        )
        .into_bytes()
    }

    /// Five honest relays' answers as the RECIPIENT validator reads them from the wire.
    fn honest() -> Vec<Answer> {
        vec![
            parse(Network::Bisq, &bisq(68_000.0, 0.0025, NOW_MS / 1000)).unwrap(),
            parse(Network::Bisq, &bisq(68_100.0, 0.0025, NOW_MS / 1000)).unwrap(),
            parse(Network::Haveno, &haveno(170.0, 0.0025, NOW_MS)).unwrap(),
            parse(Network::Haveno, &haveno(170.2, 0.0025, NOW_MS)).unwrap(),
            parse(Network::Haveno, &haveno(169.9, 0.0025, NOW_MS)).unwrap(),
        ]
    }

    /// ⭐ §21.1 — THE COMPILED RELAYS SPAN ≥ 5 RELAYS, ≥ 4 OPERATORS, ≥ 2 NETWORKS (the build check), and a list from one
    /// network, or from too few operators, is refused.
    #[test]
    fn br21_the_compiled_relays_span_five_relays_four_operators_and_two_networks() {
        assert!(list_is_diverse(RELAYS), "the release's own relay list fails its diversity check");
        let bisq_only: Vec<Relay> = RELAYS.iter().filter(|r| r.network == Network::Bisq).cloned().collect();
        assert!(!list_is_diverse(&bisq_only), "one network is not diverse");
        let mut one_operator: Vec<Relay> = RELAYS.to_vec();
        for r in &mut one_operator {
            r.operator = "same";
        }
        assert!(!list_is_diverse(&one_operator), "one operator is not diverse");
        assert!(RELAYS.iter().all(|r| r.onion.ends_with(".onion") && r.onion.len() == 62), "every relay is a v3 onion");
    }

    /// ⭐ §21.1 — EACH NETWORK'S WIRE BYTES PARSE, on the recipient validator, to $/BTC and $/XMR in that network's own
    /// convention: Bisq quotes fiat per BTC and BTC per coin; Haveno quotes counter per base, inverted when the base is not
    /// XMR. Malformed bodies parse to nothing.
    #[test]
    fn br21_each_networks_answer_parses_to_usd_per_btc_and_usd_per_xmr() {
        let b = parse(Network::Bisq, &bisq(68_000.0, 0.0025, 1_730_250_000)).unwrap();
        assert!((b.usd_per_btc - 68_000.0).abs() < 1e-6);
        assert!((b.usd_per_xmr - 170.0).abs() < 1e-6, "Bisq's XMR entry is BTC per XMR");
        assert_eq!(b.timestamp_ms, 1_730_250_000_000);
        let h = parse(Network::Haveno, &haveno(170.0, 0.0025, 1_730_250_000_000)).unwrap();
        assert!((h.usd_per_xmr - 170.0).abs() < 1e-6);
        assert!((h.usd_per_btc - 68_000.0).abs() < 1e-3, "Haveno's inverted BTC entry is undone");
        assert!(parse(Network::Bisq, b"not json").is_none());
        assert!(parse(Network::Haveno, br#"{"data":[]}"#).is_none());
        assert!(parse(Network::Bisq, &bisq(-1.0, 0.0025, 1)).is_none(), "a non-positive price is refused");
    }

    /// ⭐ §21.1 — MARK UNITS: USDm-atomic per external atomic unit × 10⁶ — BTC = $/BTC × 10⁶, XMR = $/XMR × 100.
    #[test]
    fn br21_quotes_are_in_the_marks_units() {
        let q = quote(crate::peg::NATIVE_PEG_ASSET_ID, &honest(), NOW_MS).unwrap();
        assert!((67_900_000_000..=68_100_000_000).contains(&q), "BTC mark {q}");
        let x = quote(XMR_ASSET_ID, &honest(), NOW_MS).unwrap();
        assert!((16_980..=17_020).contains(&x), "XMR mark {x}");
    }

    /// ⭐ §21.1 TAMPER — THE ADVERSARY IS ONE LYING RELAY: its answer at 2× is more than 2 % from the median, is dropped, and
    /// the quote stays at the honest relays' figure.
    #[test]
    fn br21_a_relay_lying_alone_is_dropped_as_an_outlier() {
        let mut a = honest();
        a[0] = parse(Network::Bisq, &bisq(136_000.0, 0.0025, NOW_MS / 1000)).unwrap();
        let q = quote(crate::peg::NATIVE_PEG_ASSET_ID, &a, NOW_MS).expect("four honest answers across both networks quote");
        assert!((67_900_000_000..=68_100_000_000).contains(&q), "⛔ the lie moved the quote to {q}");
    }

    /// ⭐ §21.1 TAMPER — THE ADVERSARY IS EVERY RELAY OF ONE NETWORK, colluding on a price 30 % high while the other network's
    /// relays are honest. The two networks never agree, so the lie is never quoted. CONTROL: three agreeing answers from ONE
    /// network are not enough, and fewer than three answers never quote.
    #[test]
    fn br21_relays_colluding_inside_one_network_produce_no_quote() {
        let mut a = honest();
        a[0] = parse(Network::Bisq, &bisq(88_400.0, 0.0025, NOW_MS / 1000)).unwrap();
        a[1] = parse(Network::Bisq, &bisq(88_400.0, 0.0025, NOW_MS / 1000)).unwrap();
        let q = quote(crate::peg::NATIVE_PEG_ASSET_ID, &a, NOW_MS);
        assert!(q.is_none_or(|q| q < 69_000_000_000), "⛔ a one-network lie was quoted: {q:?}");
        let haveno_only: Vec<Answer> = honest().into_iter().filter(|x| x.network == Network::Haveno).collect();
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &haveno_only, NOW_MS), None, "one network alone never quotes");
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &honest()[..2], NOW_MS), None, "fewer than three answers never quote");
    }

    /// ⭐ LOSING A WHOLE NETWORK DOES NOT STOP BITCOIN'S QUOTE, AND A THIRD NETWORK ALONE NEVER QUOTES: with every Bisq relay gone, Haveno and mempool.space agree on BTC; the mempool answers count
    /// for nothing on Monero, whose quote then stops; and two networks must still agree, so mempool.space and Haveno lying apart produce no quote.
    #[test]
    fn losing_a_whole_network_keeps_the_bitcoin_quote_and_one_network_still_never_quotes() {
        let mempool = |usd: f64| parse(Network::Mempool, format!(r#"{{"time":{},"USD":{usd}}}"#, NOW_MS / 1000).as_bytes()).unwrap();
        let no_bisq = vec![parse(Network::Haveno, &haveno(170.0, 0.0025, NOW_MS)).unwrap(), parse(Network::Haveno, &haveno(170.2, 0.0025, NOW_MS)).unwrap(), mempool(68_000.0)];
        let q = quote(crate::peg::NATIVE_PEG_ASSET_ID, &no_bisq, NOW_MS).expect("⛔ the loss of one network stopped Bitcoin's quote");
        assert!((67_900_000_000..=68_100_000_000).contains(&q), "BTC mark {q}");
        assert_eq!(quote(XMR_ASSET_ID, &no_bisq, NOW_MS), None, "a Bitcoin-only network never counts toward Monero's three");
        let only_mempool = vec![mempool(68_000.0), mempool(68_000.0), mempool(68_000.0)];
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &only_mempool, NOW_MS), None, "⛔ one network alone quoted");
        let lying = vec![mempool(88_400.0), mempool(88_400.0), parse(Network::Haveno, &haveno(170.0, 0.0025, NOW_MS)).unwrap()];
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &lying, NOW_MS), None, "⛔ one network's lie outvoted the other");
        assert!(parse(Network::Mempool, br#"{"USD":-1,"time":1}"#).is_none(), "a non-positive price is refused");
    }

    /// ⭐ §21.1 — A STALE ANSWER (older than two price epochs) is ignored; with too few fresh answers there is no quote.
    #[test]
    fn br21_a_stale_answer_is_ignored() {
        let stale_ms = NOW_MS - FRESH_MS - 1;
        let mut a = honest();
        a[2] = parse(Network::Haveno, &haveno(170.0, 0.0025, stale_ms)).unwrap();
        a[3] = parse(Network::Haveno, &haveno(170.0, 0.0025, stale_ms)).unwrap();
        a[4] = parse(Network::Haveno, &haveno(170.0, 0.0025, stale_ms)).unwrap();
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &a, NOW_MS), None, "only Bisq is fresh: no quote");
    }

    /// ⭐ §21.1 — SAMPLING: k distinct relays, a function of the validator's secret and the epoch — the same pair draws the
    /// same set; another validator or another epoch draws independently, so a relay cannot aim a lie at a known asker.
    #[test]
    fn br21_sampling_is_per_validator_and_per_epoch() {
        let s = sample(&[1u8; 32], 7, 5);
        assert_eq!(s.len(), 5.min(RELAYS.len()));
        let mut d = s.clone();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), s.len(), "distinct relays");
        assert_eq!(sample(&[1u8; 32], 7, 5), s, "deterministic for one validator and epoch");
        assert!((8..40).any(|e| sample(&[1u8; 32], e, 3) != sample(&[1u8; 32], 7, 3)), "epochs draw independently");
        assert!((0..32u8).any(|v| sample(&[v; 32], 7, 3) != sample(&[1u8; 32], 7, 3)), "validators draw independently");
    }

    /// ⭐ §21 runtime — A RELAY'S BODY IS READ WHOLE OR REFUSED: exactly the bound is read, one byte past it is refused (a
    /// hostile relay cannot make a validator buffer more); and what each simulated relay serves is read by the production
    /// parser into the same prices.
    /// TWO-PARTY-REVIEWED: the relay's side is `sim_body` (the bytes each network's pricenode serves) and the validator's is
    /// `read_bounded` + `parse` + `quote`; the quote's crossing into a chain mark is pinned in `chain_action_carriage_tests`.
    #[test]
    fn br21_a_relay_body_is_read_whole_or_refused_and_the_simulated_relays_speak_each_networks_shape() {
        let exact = vec![b' '; MAX_RESPONSE];
        assert_eq!(read_bounded(&exact[..]).map(|b| b.len()), Some(MAX_RESPONSE));
        let over = vec![b' '; MAX_RESPONSE + 1];
        assert!(read_bounded(&over[..]).is_none(), "one byte past the bound is refused");
        for i in 0..RELAYS.len() {
            let a = parse(RELAYS[i].network, &read_bounded(&sim_body(i, 60_000.0, 150.0, NOW_MS)[..]).expect("small")).expect("parses");
            assert!((a.usd_per_btc - 60_000.0).abs() < 1e-6, "relay {i}: {a:?}");
            assert!(RELAYS[i].network == Network::Mempool || (a.usd_per_xmr - 150.0).abs() < 1e-6, "relay {i}: {a:?}");
        }
        let answers: Vec<Answer> = (0..RELAYS.len()).filter_map(|i| parse(RELAYS[i].network, &sim_body(i, 60_000.0, 150.0, NOW_MS))).collect();
        assert_eq!(quote(crate::peg::NATIVE_PEG_ASSET_ID, &answers, NOW_MS), Some(60_000_000_000));
        assert_eq!(quote(XMR_ASSET_ID, &answers, NOW_MS), Some(15_000));
        assert_ne!(sampler_secret(&[1u8; 32]), sampler_secret(&[2u8; 32]));
    }
}

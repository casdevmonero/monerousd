// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! REAL Bitcoin deposit WATCHER (bridge endpoint) — the honest confirmation oracle behind Buy-USDm.
//!
//! Each bonded validator INDEPENDENTLY reads the external Bitcoin chain's PUBLIC confirmed-balance data for a
//! swap's reserve taproot address, so USDm mints ONLY after a real deposit CONFIRMS on the Bitcoin network —
//! never on a manual click, never on a simulated/faked confirmation. This is the piece that is notorious for
//! "looking complete but not being complete", so it reads a live chain source and is tested against real
//! testnet chain data (`btc_watch::tests`), not a stub.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: this module is the ONLY place the node talks to a non-MonerousD chain, and it
//! reads READ-ONLY public data (cumulative confirmed sats received at an address) — no key, no signing, no
//! classical crypto in the MonerousD base layer. ONION-ONLY AT EVERY LAYER: the query egresses ONLY through Tor
//! (MONEROUSD_TOR_SOCKS) to the explorer's Tor v3 HIDDEN SERVICE (.onion) — so the connection terminates AT the
//! hidden service with NO Tor exit node, the node's IP is never exposed, and it is not subject to the Cloudflare
//! Tor-exit block that makes the clearnet host return empty over Tor (which would stall every mint). With no Tor
//! route the watcher fails closed and NEVER reaches the external chain over a raw/direct path. FAIL-CLOSED by
//! construction: a missing Tor route, or any network / parse failure, returns `None`, so a validator that cannot
//! PRIVATELY and independently confirm the deposit does NOT attest → the mint cannot fire.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// SELF-MAINTAINING deposit cache: the last (confirmed, pending) sats per watched reserve address, refreshed by a
/// BACKGROUND loop ([`start_deposit_watch`]) so the deposit-status RPC + the mint's peg-in gate are O(1) INSTANT —
/// never blocked on the slow onion round-trip (a hidden-service fetch can take tens of seconds; doing it on the
/// RPC thread made the wallet's mint poll time out). The watcher keeps every address it has ever been asked about
/// warm, so a deposit is seen within one refresh cycle and the RPC never stalls.
struct DepositCache {
    seen: HashMap<String, (u64, u64)>, // address -> (confirmed_sats, pending_sats)
    want: HashSet<String>,             // addresses to keep refreshing forever
    // §BR-2: the coins behind `seen`, from the same source read — the attest door checks the ONE coin a co-signed
    // deposit's sweep authorization names (its value and its age against the 3-day mint window). Bounded as `want` is.
    coins: HashMap<String, Vec<ReserveCoin>>,
    // §BR-1/§BR-2: the scriptPubKeys a deposit coin's funding transaction SPENT (its senders), by coin txid — the wallet
    // refuses to cash out to one of them (paying a deposit's own sender links the exit to the entry). Filled once per coin
    // by the background loop, so the route that reads it never waits on the network. Bounded by `coins`.
    funding: HashMap<[u8; 32], Vec<Vec<u8>>>,
    // TEST BUILDS ONLY: the addresses a test placed its own coins at (`inject_confirmed_for_test`, `add_coin_for_test`). The
    // cache is process-wide and the background watcher reads whatever simulated chain another test has installed, so it must
    // never write that chain's (empty) answer over a test's own world (MEASURED 2026-10-30: a 2-of-2 peg-in pin lost its
    // injected coin to a concurrent simulator test's watcher and executed short of threshold).
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    injected: HashSet<String>,
}

fn deposit_cache() -> &'static Mutex<DepositCache> {
    static C: OnceLock<Mutex<DepositCache>> = OnceLock::new();
    C.get_or_init(|| {
        Mutex::new(DepositCache {
            seen: HashMap::new(),
            want: HashSet::new(),
            coins: HashMap::new(),
            funding: HashMap::new(),
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            injected: HashSet::new(),
        })
    })
}

/// Return `address`'s LAST CACHED (confirmed, pending) sats INSTANTLY. A PURE READ: it answers with what the
/// background sweep already holds and commits this node to no new work whatsoever.
///
/// ⛔⛔⛔ §9.6 ANSWERED FOR THIS DOOR — DOOR AUDIT 2026-09-07 (family D, the external oracle).
///  1. PROOF OF WORK — not applicable: nothing enters consensus state here; this is a cached read of public
///     external-chain data, and the mint it feeds is gated by the ≥2/3 attestation threshold, not by this.
///  2. PROOF / SIGNATURE — none, and none is due for a read. The value returned was produced by THIS node's
///     own independent read over Tor (the bundled filter watcher, §22 6), never taken from a caller's word.
///  3. CONSERVATION — the read creates no value. It is one input to the peg-in attestation gate, which
///     attests only when the deposit it reports meets the credited reserve, and mints only on threshold.
///  4. REPLAY — a repeat read is a repeat read; it changes no state, so no set is needed to refuse it.
///  5. BOUNDED WORK — THIS IS THE HOLE THAT WAS HERE. The line was `c.want.insert(address.to_string())` on
///     EVERY call, so what this node swept forever was decided by whoever called it: its outside caller is
///     the `/btc_deposit_status` route, which reads the string straight from a POST body, and
///     `start_deposit_watch` then makes ONE Tor round-trip PER ENTRY PER 8-SECOND CYCLE. The arithmetic:
///     N posted strings buy N permanent round-trips, 10,800 per entry per day, and they push the REAL
///     reserve addresses later and later in every sweep — a deposit-confirmation liveness kill on the mint
///     path, reachable from a loopback route a web page can POST to. The insert is GONE. The swept set is
///     written ONLY by [`watch_issued_reserve`], whose entries are reserve addresses this node itself
///     derived for a peg-in, and retired by [`retire_reserve_watch`] once that peg-in settles — so the
///     sweep is f(open peg-ins), never f(callers) and never f(history).
///  6. PARITY WITH THE DOOR IT PARALLELS — `deposit_confirmed` below is the synchronous sibling; it has never
///     written `want`, and now neither does this one.
///
/// ROOT-LAYER: `want` is PRODUCED here — this is the only line in the tree that ever put a caller's string
/// into the swept set. The pin's own spec says not to fix at the RPC route, because every other caller
/// would keep the hole; moving the write to a validated issuance door is that fix.
/// MEASURED: 2026-09-07, `pin_d5_the_btc_deposit_watch_set_must_be_bounded_against_a_hostile_caller` —
/// before, FAILED: "5,000 strings a hostile caller typed became 5,000 permanent sweep entries (0 -> 5000)"
/// (0 passed; 1 failed); after, ok (1 passed; 0 failed), the same 5,000 strings move the set 0 -> 0.
/// MUST-STAY-GREEN: the peg-in mint gate (`node.rs`'s deposit-confirmation attestation), the
/// `/btc_deposit_status` route's live answer, and `btc_watch::tests` — none of which reads `want`; the two
/// production readers now register through [`watch_issued_reserve`] instead, so a real reserve address is
/// swept from the moment this node issues it or a peg-in names it, exactly as before.
/// cons: none — a caller naming an address this node never issued still gets whatever the cache holds for
/// it, unchanged; it simply buys no sweep work. No answer is destroyed and nothing is refused.
pub fn confirmed_pending_cached(address: &str) -> (u64, u64) {
    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.seen.get(address).copied().unwrap_or((0, 0))
}

/// THE ONE WRITER of the swept set — this node committing to watch a reserve address IT produced.
///
/// Called where a reserve address becomes real business for this node: `Node::reserve_addresses`, which
/// derives it from the LIVE bonded custody set, and the peg-in attestation gate, which must sweep the
/// address a peg-in names in order to confirm it independently (a peer attesting for someone else's deposit
/// never called the issuance route, so registering only at issuance would silently block every
/// multi-validator mint — that is why the attestation gate is the second registrar and not a second door).
///
/// VALIDATED AT THE DOOR, so a malformed or foreign string can never become sweep work even from an
/// internal caller: the address must be a Bitcoin bech32/bech32m address on a Bitcoin network (`bc1…`
/// mainnet, `tb1…` testnet, `bcrt1…` regtest). Which network this node's source is on is the source's own
/// business: an address from another network reads no coin there. Measured 2026-09-21: a real 30 BTC regtest
/// deposit read as 0 for 600 s because this door knew only `tb1`/`bc1` and refused the run's own `bcrt1…`
/// reserve address as foreign. Returns whether it is now watched.
pub fn watch_issued_reserve(address: &str) -> bool {
    let a = address.trim();
    // BY CONSTRUCTION, from BIP173/BIP350's own shape — not a tuned figure: a segwit address is
    // `hrp ‖ '1' ‖ data`, at most 90 characters, never fewer than 14, written in lower-case bech32.
    // Anything else is not an address this watcher could ever read a balance for.
    let network_ok = a.starts_with("tb1") || a.starts_with("bc1") || a.starts_with("bcrt1");
    let mut shape_ok = a.len() >= 14 && a.len() <= 90;
    for b in a.as_bytes() {
        let lower = *b >= b'a' && *b <= b'z';
        let digit = *b >= b'0' && *b <= b'9';
        if !lower && !digit {
            shape_ok = false;
        }
    }
    if !network_ok || !shape_ok {
        // Fixed string — by construction no address, amount, key or owner can appear in it.
        eprintln!(
            "[btc-watch] ⛔ REFUSED a reserve-watch registration: the string is not a bech32 address on a \
             network this watcher bridges. Nothing added to the sweep."
        );
        return false;
    }
    let mut c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.want.insert(a.to_string());
    true
}

/// RETIRE a swept reserve address — the other half of what makes the sweep f(open peg-ins). Called once the
/// peg-in an address was issued for has settled, so the set holds pending business and nothing else. The
/// last answer stays in `seen`, so a later status read still returns what this node measured; only the
/// recurring Tor round-trip stops.
pub fn retire_reserve_watch(address: &str) {
    let mut c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.want.remove(address.trim());
    crate::btc_neutrino::retire_address(address.trim()); // §22 6: the bundled watcher drops a settled swap's address too
}

/// TEST-ONLY (`#[cfg(test)]`, compiled out of every release build): how many addresses the background
/// watcher is committed to re-fetching over Tor forever. Read by the Family-D door audit's bounded-work
/// pin (`family_d_door_audit_tests::pin_d5_…`) — the absence of a bound has no other runtime handle.
///
/// ROOT-LAYER: this is a READ-ONLY audit probe on `DepositCache.want`, which is where the unbounded
/// growth is PRODUCED (`confirmed_pending_cached` inserts into it). It changes no value and fixes
/// nothing — the fix belongs at the producer and is specified in the pin; this only makes the producer's
/// behaviour observable so the pin can be RED for a measured reason instead of an argued one. The
/// poison arm mirrors every other lock read in this file (`.unwrap_or_else(|e| e.into_inner())`), so a
/// panicking watcher thread cannot turn an audit read into a second panic.
/// MEASURED: before — the set size was unobservable from any test, so "unbounded" was a source claim;
/// after — 5,000 hostile strings through `confirmed_pending_cached` move the count 0 -> 5,000 (the
/// number the pin asserts against).
/// MUST-STAY-GREEN: nothing in a release build can call it (`#[cfg(test)]`); `btc_watch::tests`, the
/// peg-in mint-gate tests, and `rpc_http`'s `/btc_deposit_status` path are untouched.
#[cfg(test)]
pub fn watch_set_len_for_audit() -> usize {
    deposit_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .want
        .len()
}

/// TEST-ONLY (dev builds under `#[cfg(test)]` or the `bridge-test-oracle` feature — COMPILED OUT of production
/// entirely): inject a CONFIRMED on-chain deposit for `address` so the peg-in mint gate can be driven e2e WITHOUT
/// sending real BTC/XMR (no funds-loss risk). The gate itself stays REAL — this only supplies the confirmation the
/// live [`start_deposit_watch`] watcher would read from the chain. A release build has no such function, so there
/// is no free-mint bypass in production.
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub fn inject_confirmed_for_test(address: &str, sats: u64) {
    let mut c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.injected.insert(address.to_string());
    c.seen.insert(address.to_string(), (sats, 0));
    // §BR-2: and the coin itself, as the watcher would read it — matured, one confirmation into the mint window
    let mut h = blake3::Hasher::new_derive_key("MUSD/test/injected-deposit-coin/v1");
    h.update(address.as_bytes());
    let coin = ReserveCoin { txid: *h.finalize().as_bytes(), vout: 0, value_sats: sats, confirmations: required_confirmations(sats) };
    c.coins.insert(address.to_string(), vec![coin]);
}

/// Start the self-maintaining deposit watcher exactly once: a background thread that refreshes every watched
/// address's (confirmed, pending) sats over the onion pool on a fixed cadence and stores them in the cache, so
/// every RPC / mint check stays O(1) instant and always current. Auto-heals: a failed refresh just retries next
/// cycle; a filter peer that breaks a rule or leaves is replaced by the bundled watcher. Idempotent — a second call is a no-op.
pub fn start_deposit_watch() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(|| loop {
        let addrs: Vec<String> = {
            let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
            c.want.iter().cloned().collect()
        };
        for a in addrs {
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            if deposit_cache().lock().unwrap_or_else(|e| e.into_inner()).injected.contains(&a) {
                continue; // a test's own coins: never overwritten by another world's read
            }
            // DB-121/DB-122: "confirmed" means MATURED — each coin has waited THORChain's ⌈value/subsidy⌉
            // confirmations (`required_confirmations`), so a one-block reorg can never unwind a deposit worth
            // more than a block reward after it minted. The count is taken from this node's OWN source read.
            let src = btc_source(net_of_address(&a));
            if let Some(coins) = src.as_ref().and_then(|src| src.utxos(&a)) {
                let (matured, pend) = matured_and_pending_of(&coins);
                let need: Vec<[u8; 32]> = {
                    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
                    coins.iter().map(|k| k.txid).filter(|t| !c.funding.contains_key(t)).collect()
                };
                let fetched: Vec<([u8; 32], Vec<Vec<u8>>)> = need
                    .into_iter()
                    .filter_map(|t| src.as_ref()?.funding_scripts(&crate::btc_tx::txid_display_hex(&t)).map(|f| (t, f)))
                    .collect();
                let mut c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
                c.seen.insert(a.clone(), (matured, pend));
                c.coins.insert(a, coins);
                for (t, f) in fetched {
                    c.funding.insert(t, f);
                }
            }
        }
        std::thread::sleep(Duration::from_secs(8));
    });
}

/// §22 6: read ONLY for the public `/fee-estimates` (names no address or transaction) — deposits and payouts are read by
/// the bundled filter watcher. Built-in Tor v3 HIDDEN SERVICE Esplora bases (host only, no `/api`). Each is a `.onion` so it stays
/// ONION-ONLY (the connection terminates AT the hidden service — no Tor exit node, no IP leak) AND avoids the
/// Cloudflare Tor-EXIT block that makes the clearnet host return empty over Tor. mempool.space's onion is the
/// verified testnet4 + mainnet source; the pool is extended at runtime by operators/governance (see `esplora_bases`).
const BUILTIN_ESPLORA_ONIONS: &[&str] =
    &["http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion"];

/// The SELF-HEALING POOL of Tor-reachable Esplora REST bases for the Bitcoin network. The watcher tries these IN
/// ORDER and fails over to the next when one is unreachable — so a single dead source NEVER halts a mint (auto-
/// healing, like the node mesh). Runtime-extensible without a code change: `MONEROUSD_BTC_ESPLORA_ONIONS` (a
/// comma-separated list of `.onion` hosts, each WITHOUT the `/api` or network segment) is prepended to the pool,
/// so operators/governance can add sources as they come online. Testnet vs mainnet is selected by the reserve
/// address's own network (`tb1…` = testnet, `bc1…` = mainnet) so the watcher can never confirm a testnet deposit
/// against mainnet or vice-versa. The testnet endpoint is Bitcoin TESTNET4 (testnet3's public faucets went
/// drained/unreliable; testnet4 shares the `tb1…` HRP, so reserve addresses are byte-identical).
pub fn esplora_bases(testnet: bool) -> Vec<String> {
    let seg = if testnet { "/testnet4/api" } else { "/api" };
    let mut bases: Vec<String> = Vec::new();
    if let Ok(extra) = std::env::var("MONEROUSD_BTC_ESPLORA_ONIONS") {
        for b in extra
            .split(',')
            .map(|s| s.trim().trim_end_matches('/'))
            .filter(|s| !s.is_empty())
        {
            bases.push(format!("{b}{seg}"));
        }
    }
    for b in BUILTIN_ESPLORA_ONIONS {
        bases.push(format!("{}{seg}", b.trim_end_matches('/')));
    }
    bases
}

/// True iff a bech32(m) address is a Bitcoin TESTNET address (HRP `tb`). A mainnet `bc1…`/`bc1p…` returns false.
pub fn is_testnet_address(address: &str) -> bool {
    let a = address.trim().to_ascii_lowercase();
    a.starts_with("tb1")
}

/// A Tor-ONLY HTTP agent for the bridge watch. Returns `None` when no Tor SOCKS proxy is configured
/// (`MONEROUSD_TOR_SOCKS` unset/empty) or the proxy cannot be built — the watcher then fails closed and NEVER
/// egresses over a raw/direct path. This is what keeps the bridge endpoint onion-only at every layer: the node
/// reaches the external chain THROUGH Tor or not at all, so its IP is never revealed to the bridge source.
pub fn agent() -> Option<ureq::Agent> {
    let socks = std::env::var("MONEROUSD_TOR_SOCKS")
        .ok()
        .filter(|s| !s.is_empty())?;
    // ureq's SOCKS5 sends the TARGET host to the proxy as a Domain (remote resolution), so the `.onion` is
    // resolved BY Tor — exactly what a hidden service needs. (ureq 2.x has no `socks5h` scheme; `socks5` already
    // does remote target resolution — only the proxy host is resolved locally, never the target.)
    let proxy = ureq::Proxy::new(format!("socks5://{socks}")).ok()?;
    // Hidden-service round-trips are slower; allow headroom so a healthy deposit isn't missed on the first poll.
    Some(
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(25))
            .proxy(proxy)
            .build(),
    )
}

/// True iff the reserve `address` has received at least `min_sats` in CONFIRMED Bitcoin transactions — the
/// deposit-confirmed gate a validator checks before it will attest a peg-in. `min_sats == 0` is never a pass
/// (a swap always requires a positive deposit); a failed lookup is never a pass (fail-closed).
pub fn deposit_confirmed(address: &str, min_sats: u64) -> bool {
    // Reads the SELF-MAINTAINING cache (O(1) instant, kept fresh by the background watcher) — never blocks the
    // mint gate on a slow onion round-trip. Registers the address so it stays warm for subsequent checks.
    min_sats > 0 && confirmed_pending_cached(address).0 >= min_sats
}

// ═══════════════════ DB-121 — the reserve's coin view, the payout's broadcast path, and confirmation counting ═══════════════════
//
// Everything the exit leg needs from Bitcoin, behind ONE source type: the confirmed coins at a reserve address,
// a coin's value and script, a transaction's depth, the fee market, and a broadcast. Two backends, both chosen by
// configuration and both private by construction: the bundled filter watcher over Bitcoin's own onion peers (§22 6),
// or the operator's OWN Bitcoin Core (`MONEROUSD_BTC_RPC_URL`) — the most trustless source
// there is, and the one the regtest oracle rig drives. A Core URL is accepted ONLY on this machine (127.0.0.1)
// or as a `.onion`; a clearnet host would hand the node's IP to whoever runs it, so it is refused, loudly.

/// Bitcoin's block subsidy after the 2024 halving, in satoshis (3.125 BTC).
pub const BTC_BLOCK_SUBSIDY_SATS: u64 = 312_500_000;

/// THORChain's confirmation counting, borrowed whole (DB-122, the flash-loan class on the inbound edge): a coin of
/// `value_sats` is final after `⌈value / block subsidy⌉` confirmations, at least one. To unwind it an attacker
/// must reorg as many blocks as the coin is worth in subsidies, so the reorg costs more than the coin — the rule
/// THORChain has run on Bitcoin since 2021. A WAIT, never a cap: a larger deposit waits longer and is never
/// refused (user 2026-09-20: "i dont want any deposit or withdrawl caps").
pub fn required_confirmations(value_sats: u64) -> u64 {
    value_sats.div_ceil(BTC_BLOCK_SUBSIDY_SATS).max(1)
}

/// One coin at a reserve address as the source reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveCoin {
    /// Internal byte order (see `btc_tx::txid_from_display_hex`).
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    /// 0 = seen but unconfirmed.
    pub confirmations: u64,
}

impl ReserveCoin {
    /// Final under THORChain's counting — spendable by a payout, countable toward a mint.
    pub fn matured(&self) -> bool {
        self.confirmations >= required_confirmations(self.value_sats)
    }
}

/// Where this node reads Bitcoin from and hands a payout to.
#[derive(Clone)]
pub enum BtcSource {
    /// ⭐ §22 6 — the BUNDLED watcher (`btc_neutrino`): Bitcoin's own peers over the node's Tor, headers followed by
    /// Bitcoin's rules, every block's filter agreed by three peers, matched blocks checked against their headers. No
    /// explorer is trusted for an answer or told an address. (The fee estimate alone is read from the explorer pool's
    /// public `/fee-estimates`, which names nothing.)
    Neutrino { net: crate::btc_tx::BtcNet },
    /// The operator's own Bitcoin Core over JSON-RPC, on this machine or through a `.onion`.
    CoreRpc { url: String, auth_header: String, agent: ureq::Agent },
    /// §NETSIM-LAUNCH: the simulator's in-process Bitcoin (`btc_sim`, Bitcoin Core regtest semantics on the sim clock),
    /// installed by a pin or a netsim journey; absent from a release daemon.
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    Sim(std::sync::Arc<std::sync::Mutex<crate::btc_sim::SimBitcoin>>),
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// The configured Bitcoin source for `net`, or `None` when this node has no private route to Bitcoin at all
/// (no Tor SOCKS and no same-host/onion Core) — every caller then does nothing, never reaches out in the clear.
pub fn btc_source(net: crate::btc_tx::BtcNet) -> Option<BtcSource> {
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    if let Some(sim) = crate::btc_sim::installed() {
        return Some(BtcSource::Sim(sim));
    }
    if let Ok(url) = std::env::var("MONEROUSD_BTC_RPC_URL") {
        if !url.trim().is_empty() {
            let url = url.trim().trim_end_matches('/').to_string();
            let after_scheme = url.split("://").nth(1)?;
            let hostport = after_scheme.split('/').next()?.rsplit('@').next()?;
            let host = if hostport.starts_with('[') {
                hostport.split(']').next()?.trim_start_matches('[')
            } else {
                hostport.split(':').next()?
            };
            let same_host = matches!(host, "127.0.0.1" | "localhost" | "::1");
            let onion = host.ends_with(".onion");
            if !same_host && !onion {
                eprintln!("[btc-source] ⛔ MONEROUSD_BTC_RPC_URL names a clearnet host — a Bitcoin Core source is this machine (127.0.0.1) or .onion only; ignoring it");
                return None;
            }
            let agent = if onion {
                agent()?
            } else {
                // A Core on this machine needs no Tor route; the 30 s bound only stops a hung RPC from holding
                // the lane's tick — the tick asks again next cycle, nothing is decided by it.
                ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build()
            };
            let creds = match std::env::var("MONEROUSD_BTC_RPC_AUTH") {
                Ok(a) if !a.trim().is_empty() => a.trim().to_string(),
                _ => {
                    let cookie_path = std::env::var("MONEROUSD_BTC_RPC_COOKIE").ok()?;
                    std::fs::read_to_string(cookie_path).ok()?.trim().to_string()
                }
            };
            return Some(BtcSource::CoreRpc { url, auth_header: format!("Basic {}", base64(creds.as_bytes())), agent });
        }
    }
    if net == crate::btc_tx::BtcNet::Regtest {
        return None; // a regtest chain has no public explorer — it is reached through its own Core only
    }
    agent()?; // the node's Tor route — none, no watcher (never a direct path)
    crate::btc_neutrino::start(net);
    Some(BtcSource::Neutrino { net })
}

/// Say what Bitcoin Core refused, in its own words when it gave them.
fn log_core_error(method: &str, err: &serde_json::Value) {
    match err["message"].as_str() {
        Some(m) => eprintln!("[btc-source] core {method}: {m}"),
        None => eprintln!("[btc-source] core {method}: refused without a message: {err}"),
    }
}

/// ⭐ BITCOIN CORE RUNS ONE UTXO-SET SCAN AT A TIME (per Core process: `scantxoutset` answers "Scan already in progress"
/// to every other caller). MEASURED 2026-11-10 (launch_trade.py round 23, real nodes): the two nodes of the rig share one
/// regtest Core and each scans from its tick and its watcher, so 423 and 413 scans were refused that way; each refusal read
/// as an address with NO coins — the payout proposer skipped the reserve ("not proposing: the matured reserve coins this
/// node sees do not cover 10000 sats plus the fee", 176 times) with 0.00020693 BTC still owed, and both nodes raised a
/// solvency hold that refuses new issuance. A busy scan is not an empty reserve: the newest view this node read of the
/// address answers instead (`CORE_LAST`), and this process never starts a second scan while one of its own runs.
/// O1-FOOTPRINT-REVIEWED: one coin list per address this node scans (the reserve's and the watched deposits', as `want`).
static CORE_SCAN: Mutex<()> = Mutex::new(());
fn core_last() -> &'static Mutex<HashMap<String, Vec<ReserveCoin>>> {
    static C: OnceLock<Mutex<HashMap<String, Vec<ReserveCoin>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}
const CORE_SCAN_BUSY: &str = "Scan already in progress";

impl BtcSource {
    fn core_call(&self, method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
        match self.core_answer(method, params) {
            Ok(v) => Some(v),
            Err(Some(err)) => {
                log_core_error(method, &err);
                None
            }
            Err(None) => None,
        }
    }

    /// One Core call: its result, or Core's own error object (`Err(Some)`), or no answer at all (`Err(None)`).
    fn core_answer(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Option<serde_json::Value>> {
        let BtcSource::CoreRpc { url, auth_header, agent } = self else {
            return Err(None);
        };
        let body = serde_json::json!({ "jsonrpc": "1.0", "id": "usdmd", "method": method, "params": params });
        let resp = agent
            .post(url)
            .set("Authorization", auth_header)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let v: serde_json::Value = match resp {
            Ok(r) => r.into_json().map_err(|_| None)?,
            Err(ureq::Error::Status(_, r)) => {
                // Bitcoin Core answers an RPC error with HTTP 500 and the error in the body — read it out loud.
                let v: serde_json::Value = r.into_json().map_err(|_| None)?;
                return Err(Some(v["error"].clone()));
            }
            Err(_) => return Err(None),
        };
        if !v["error"].is_null() {
            return Err(Some(v["error"].clone()));
        }
        Ok(v["result"].clone())
    }

    /// Core's UTXO scan of one address, under the one-scan rule (see [`CORE_SCAN`]).
    fn core_utxos(&self, address: &str) -> Option<Vec<ReserveCoin>> {
        // SAFE-FALLBACK: while a scan is running — this process's own (it is never started twice) or another's on the same
        // Core — the address's newest view this node read answers. It can only be older, never invented: a coin a payout
        // has since spent makes that proposal fail at Core's own double-spend refusal and be built again, and a recorded
        // depth only understates a coin's maturity. An address never read yet still answers nothing.
        let newest = || core_last().lock().unwrap_or_else(|e| e.into_inner()).get(address).cloned();
        let Ok(_one) = CORE_SCAN.try_lock() else {
            return newest();
        };
        let r = match self.core_answer("scantxoutset", serde_json::json!(["start", [{ "desc": format!("addr({address})") }]])) {
            Ok(r) => r,
            Err(Some(err)) if err["message"].as_str().is_some_and(|m| m.contains(CORE_SCAN_BUSY)) => return newest(),
            Err(Some(err)) => {
                log_core_error("scantxoutset", &err);
                return None;
            }
            Err(None) => return None,
        };
        let tip = r["height"].as_u64()?;
        let mut coins = Vec::new();
        for u in r["unspents"].as_array()? {
            let height = u["height"].as_u64()?;
            coins.push(ReserveCoin {
                txid: crate::btc_tx::txid_from_display_hex(u["txid"].as_str()?)?,
                vout: u["vout"].as_u64()? as u32,
                value_sats: (u["amount"].as_f64()? * 1e8).round() as u64,
                confirmations: tip.saturating_sub(height).saturating_add(1),
            });
        }
        core_last().lock().unwrap_or_else(|e| e.into_inner()).insert(address.to_string(), coins.clone());
        Some(coins)
    }

    /// The source's chain tip height.
    pub fn tip_height(&self) -> Option<u64> {
        match self {
            BtcSource::CoreRpc { .. } => self.core_call("getblockcount", serde_json::json!([]))?.as_u64(),
            BtcSource::Neutrino { net } => crate::btc_neutrino::with_watch(*net, |w| u64::from(w.follower.tip().height)),
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => Some(s.lock().unwrap_or_else(|e| e.into_inner()).tip_height()),
        }
    }

    /// The UNSPENT coins at `address` with their depth: the bundled watcher's coins from committed blocks (no mempool —
    /// a light client asks for no transaction relay); Bitcoin Core's UTXO scan reports confirmed coins only.
    pub fn utxos(&self, address: &str) -> Option<Vec<ReserveCoin>> {
        match self {
            BtcSource::CoreRpc { .. } => self.core_utxos(address),
            BtcSource::Neutrino { net } => {
                crate::btc_neutrino::watch_address(address); // registered for the next sweep; its coins once a block shows them
                crate::btc_neutrino::with_watch(*net, |w| w.reserve_coins(address))
            }
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => s.lock().unwrap_or_else(|e| e.into_inner()).utxos(address),
        }
    }

    /// One output of a transaction: `(value_sats, scriptPubKey)`.
    pub fn tx_out(&self, txid_display: &str, vout: u32) -> Option<(u64, Vec<u8>)> {
        match self {
            BtcSource::CoreRpc { .. } => {
                let t = self.core_call("getrawtransaction", serde_json::json!([txid_display, true]))?;
                let o = &t["vout"][vout as usize];
                Some(((o["value"].as_f64()? * 1e8).round() as u64, crate::btc_tx::unhex(o["scriptPubKey"]["hex"].as_str()?)?))
            }
            BtcSource::Neutrino { net } => {
                let txid = crate::btc_tx::txid_from_display_hex(txid_display)?;
                crate::btc_neutrino::with_watch(*net, |w| w.tx_out(&txid, vout))?
            }
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => s.lock().unwrap_or_else(|e| e.into_inner()).tx_out(txid_display, vout),
        }
    }

    /// §BR-1/§BR-2 — the scriptPubKeys the transaction's inputs spent (who sent it). `None` when the source cannot say.
    pub fn funding_scripts(&self, txid_display: &str) -> Option<Vec<Vec<u8>>> {
        match self {
            BtcSource::CoreRpc { .. } => {
                // verbosity 2 carries each input's prevout (Bitcoin Core ≥ 25)
                let t = self.core_call("getrawtransaction", serde_json::json!([txid_display, 2]))?;
                t["vin"].as_array()?.iter().map(|i| crate::btc_tx::unhex(i["prevout"]["scriptPubKey"]["hex"].as_str()?)).collect()
            }
            BtcSource::Neutrino { net } => {
                let txid = crate::btc_tx::txid_from_display_hex(txid_display)?;
                crate::btc_neutrino::with_watch(*net, |w| w.funding_scripts(&txid))?
            }
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => s.lock().unwrap_or_else(|e| e.into_inner()).funding_scripts(txid_display),
        }
    }

    /// How deep a transaction is: `Some(0)` seen but unconfirmed, `None` unknown to this source.
    pub fn tx_confirmations(&self, txid_display: &str) -> Option<u64> {
        match self {
            BtcSource::CoreRpc { .. } => {
                let t = self.core_call("getrawtransaction", serde_json::json!([txid_display, true]))?;
                // Bitcoin Core's verbose decode carries `confirmations` only once the transaction is in a
                // block; a mempool transaction has no such field, which is exactly "seen, unconfirmed".
                Some(match t["confirmations"].as_u64() {
                    Some(c) => c,
                    None => 0,
                })
            }
            BtcSource::Neutrino { net } => {
                let txid = crate::btc_tx::txid_from_display_hex(txid_display)?;
                crate::btc_neutrino::with_watch(*net, |w| w.tx_confirmations(&txid))?
            }
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => s.lock().unwrap_or_else(|e| e.into_inner()).tx_confirmations(txid_display),
        }
    }

    /// Hand a signed transaction to the network; the txid as the source reports it.
    pub fn broadcast(&self, raw_hex: &str) -> Option<String> {
        match self {
            BtcSource::CoreRpc { .. } => Some(self.core_call("sendrawtransaction", serde_json::json!([raw_hex]))?.as_str()?.to_string()),
            BtcSource::Neutrino { net } => crate::btc_neutrino::broadcast(*net, &crate::btc_tx::unhex(raw_hex)?), // to the filter peers
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => match s.lock().unwrap_or_else(|e| e.into_inner()).broadcast(raw_hex) {
                Ok(txid) => Some(txid),
                Err(e) => {
                    eprintln!("[btc-source] sim sendrawtransaction: {e}");
                    None
                }
            },
        }
    }

    /// The fee rate a payout pays, in sat/vB: `MONEROUSD_BTC_FEE_RATE_SAT_VB` when the operator pins one (the
    /// regtest rig does — a fresh regtest chain has no fee market to estimate), else the source's 6-block estimate.
    /// `None` when neither answers — the proposer then waits; it never guesses a fee.
    /// This node's own Bitcoin fee estimate (sat/vB, 6-block target), read from [`fee_cache`] and NEVER fetched on the
    /// caller's thread.
    ///
    /// ⭐ LOCK-NET-IO (lane livewedge, 2026-11-26, docs/UX-DEEP-AUDIT-20261126.md U15). MEASURED on the live origin
    /// (`sample` of pid 1561, 15 s): `PayoutLane::tick` → this function → `ureq` over Tor took 1,908 of the payout tick's
    /// 1,912 samples. Every caller runs on the runtime lock (`main.rs` `rt.lock()` → `tick_relay` → `lanes_every_tick` →
    /// `payout_lane_tick`; `/btc_cashout_fee_quote` holds `rt.lock()` around it). The agent's timeout is 25 s (`agent()`), so
    /// one slow onion answer held every RPC, the pump and production for up to 25 s; the log's slow holds reached 34,800 ms.
    ///
    /// The shape: stale-while-revalidate. A reading at most [`fee_cache::REFRESH_MS`] old is served as is. An older one
    /// starts ONE background fetch per source (in-flight dedupe) and is still served until [`fee_cache::MAX_AGE_MS`]. Past
    /// that, `None`. Every caller already reads `None` as "no estimate of my own" (it refuses or skips the item this tick and
    /// asks again on the next), the meaning a failed fetch had before. A Bitcoin fee estimate moves on Bitcoin's block
    /// timescale (~600 s), so a reading ≤ 30 s old prices a fee as a fresh one would.
    /// Long-term effects: at most [`fee_cache::SLOTS_MAX`] slots, one per configured source, overwritten in place, and at most
    /// one fetch thread per slot. Nothing accumulates across reorgs, restarts or joins. A restart starts cold, and the first
    /// tick's `None` is the "source not answering" case the callers already handle.
    /// AI resistance: (b). The estimate is this node's own reading of an outside source; a quorum signs only what each
    /// custodian's own estimate admits (`refuse` at the callers), unchanged.
    pub fn fee_rate_sat_vb(&self) -> Option<u64> {
        if let Ok(v) = std::env::var("MONEROUSD_BTC_FEE_RATE_SAT_VB") {
            if let Ok(n) = v.trim().parse::<u64>() {
                return Some(n.max(1));
            }
        }
        #[cfg(any(test, feature = "bridge-test-oracle"))]
        if let BtcSource::Sim(s) = self {
            return Some(s.lock().unwrap_or_else(|e| e.into_inner()).fee_rate_sat_vb());
        }
        fee_cache::read_or_refresh(self)
    }

    fn fee_cache_key(&self) -> String {
        match self {
            BtcSource::Neutrino { net } => format!("neutrino:{net:?}"),
            BtcSource::CoreRpc { url, .. } => format!("core:{url}"),
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(_) => "sim".to_string(),
        }
    }

    /// The network fetch itself, run only on a [`fee_cache`] refresh thread.
    fn fee_rate_fetch(&self) -> Option<u64> {
        match self {
            BtcSource::CoreRpc { .. } => {
                let r = self.core_call("estimatesmartfee", serde_json::json!([6]))?;
                let btc_per_kvb = r["feerate"].as_f64()?;
                Some(((btc_per_kvb * 1e8 / 1000.0).ceil() as u64).max(1))
            }
            BtcSource::Neutrino { net } => {
                // a light client has no mempool: the 6-block estimate is the explorer pool's PUBLIC /fee-estimates over
                // onion — it names no address or transaction, and a wrong figure costs fees, never funds
                let agent = agent()?;
                esplora_bases(*net == crate::btc_tx::BtcNet::Testnet).into_iter().find_map(|base| {
                    let r: serde_json::Value = agent.get(&format!("{base}/fee-estimates")).call().ok()?.into_json().ok()?;
                    Some((r["6"].as_f64()?.ceil() as u64).max(1))
                })
            }
            #[cfg(any(test, feature = "bridge-test-oracle"))]
            BtcSource::Sim(s) => Some(s.lock().unwrap_or_else(|e| e.into_inner()).fee_rate_sat_vb()),
        }
    }
}

/// The Bitcoin network an address string belongs to, from its prefix.
/// The fee estimate's off-lock cache ([`BtcSource::fee_rate_sat_vb`] says why).
/// Bound: [`SLOTS_MAX`] slots of (key, rate, fetched-at), a constant; one refresh thread per slot at most.
pub(crate) mod fee_cache {
    use super::BtcSource;
    use std::sync::Mutex;

    /// A reading younger than this is served with no refresh.
    pub const REFRESH_MS: u64 = 30_000;
    /// A reading older than this is never served (`None`: the caller refuses or skips the item this tick).
    pub const MAX_AGE_MS: u64 = 600_000;
    /// Slots: one per configured source (Neutrino per network, a Core RPC per url). A constant, never f(history).
    pub const SLOTS_MAX: usize = 8;

    struct Slot {
        key: String,
        rate: Option<u64>,
        at_ms: u64,
        fetching: bool,
    }

    static SLOTS: Mutex<Vec<Slot>> = Mutex::new(Vec::new());

    fn now_ms() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
    }

    fn slots() -> std::sync::MutexGuard<'static, Vec<Slot>> {
        SLOTS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The served reading, and at most one refresh started; never a network call on this thread.
    pub(super) fn read_or_refresh(src: &BtcSource) -> Option<u64> {
        let key = src.fee_cache_key();
        let now = now_ms();
        let (served, start) = {
            let mut g = slots();
            if !g.iter().any(|s| s.key == key) {
                if g.len() >= SLOTS_MAX {
                    // the least recently fetched slot gives way (a source the node no longer reads)
                    if let Some(i) = (0..g.len()).filter(|&i| !g[i].fetching).min_by_key(|&i| g[i].at_ms) {
                        g.remove(i);
                    }
                }
                if g.len() < SLOTS_MAX {
                    g.push(Slot { key: key.clone(), rate: None, at_ms: 0, fetching: false });
                }
            }
            match g.iter_mut().find(|s| s.key == key) {
                Some(s) => {
                    let age = now.saturating_sub(s.at_ms);
                    let served = s.rate.filter(|_| age <= MAX_AGE_MS);
                    let start = !s.fetching && (s.rate.is_none() || age >= REFRESH_MS);
                    if start {
                        s.fetching = true;
                    }
                    (served, start)
                }
                None => (None, false),
            }
        };
        if start {
            let owned = src.clone();
            let spawned = std::thread::Builder::new().name("btc-fee-refresh".into()).spawn(move || {
                let rate = owned.fee_rate_fetch();
                let done = now_ms();
                let mut g = slots();
                if let Some(s) = g.iter_mut().find(|s| s.key == key) {
                    s.fetching = false;
                    if let Some(r) = rate {
                        s.rate = Some(r);
                        s.at_ms = done;
                    }
                }
            });
            if spawned.is_err() {
                // no thread this time: clear the mark so the next call starts one
                if let Some(s) = slots().iter_mut().find(|s| s.key == src.fee_cache_key()) {
                    s.fetching = false;
                }
            }
        }
        served
    }

    #[cfg(test)]
    pub(super) fn reset() {
        slots().clear();
    }
}

pub fn net_of_address(address: &str) -> crate::btc_tx::BtcNet {
    let a = address.trim().to_ascii_lowercase();
    if a.starts_with("bcrt1") {
        crate::btc_tx::BtcNet::Regtest
    } else if is_testnet_address(&a) || a.starts_with('m') || a.starts_with('n') || a.starts_with('2') {
        crate::btc_tx::BtcNet::Testnet
    } else {
        crate::btc_tx::BtcNet::Mainnet
    }
}

/// `(matured, pending)` sats at `address`: the unspent coins that have waited their required confirmations, and
/// those still waiting (or unconfirmed). Read from this node's own configured source over its private route.
pub fn matured_and_pending(address: &str) -> Option<(u64, u64)> {
    let src = btc_source(net_of_address(address))?;
    let coins = src.utxos(address)?;
    Some(matured_and_pending_of(&coins))
}

/// (matured, pending) sats of a coin list — the one sum every reader takes.
fn matured_and_pending_of(coins: &[ReserveCoin]) -> (u64, u64) {
    let mut matured = 0u64;
    let mut pending = 0u64;
    for c in coins {
        if c.matured() {
            matured = matured.saturating_add(c.value_sats);
        } else {
            pending = pending.saturating_add(c.value_sats);
        }
    }
    (matured, pending)
}

/// §BR-2 — every coin this node's watcher holds at `address` (a cache read).
#[must_use]
pub fn coins_cached(address: &str) -> Vec<ReserveCoin> {
    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.coins.get(address).cloned().unwrap_or_default()
}

/// §BR-1/§BR-2 — the scripts a coin's funding transaction spent, if the watcher has read them (a cache read).
#[must_use]
pub fn funding_scripts_cached(txid: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.funding.get(txid).cloned()
}

/// TEST-ONLY: record a coin's funding scripts as the watcher would read them.
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub fn set_funding_for_test(txid: [u8; 32], scripts: Vec<Vec<u8>>) {
    deposit_cache().lock().unwrap_or_else(|e| e.into_inner()).funding.insert(txid, scripts);
}

/// ⭐ §BR-2 — the ONE coin a co-signed deposit's sweep authorization names, as this node's own source last read it: a
/// cache read (O(1), never a network call on the attest path); `None` when this node has not seen it at the address.
#[must_use]
pub fn deposit_coin(address: &str, txid: &[u8; 32], vout: u32) -> Option<ReserveCoin> {
    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.coins.get(address)?.iter().find(|k| &k.txid == txid && k.vout == vout).cloned()
}

/// TEST-ONLY: place one MORE coin at `address` beside the injected one (the §BR-2 mint-window arm names an old coin of its
/// own, so no other test's coin at the same address ever changes).
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub fn add_coin_for_test(address: &str, coin: ReserveCoin) {
    let mut c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.injected.insert(address.to_string());
    let v = c.coins.entry(address.to_string()).or_default();
    v.retain(|k| !(k.txid == coin.txid && k.vout == coin.vout));
    v.push(coin);
}

/// TEST-ONLY: the coin [`inject_confirmed_for_test`] places at `address` — what a test's wallet signs its sweep over.
#[cfg(any(test, feature = "bridge-test-oracle"))]
#[must_use]
pub fn injected_coin_for_test(address: &str) -> ReserveCoin {
    let c = deposit_cache().lock().unwrap_or_else(|e| e.into_inner());
    c.coins.get(address).and_then(|v| v.first().cloned()).expect("inject_confirmed_for_test placed a coin here")
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ LOCK-NET-IO: the fee estimate never makes its caller wait on the network.
    /// A Core RPC that accepts a connection and answers only after 3 s must cost the caller no time (`None` at once, the
    /// "no estimate of my own" every caller already handles), and the answer must be served once the background fetch has it.
    /// Fails on the old shape: the first call blocked the full 3 s on its own thread (under the runtime lock, live: up to 25 s).
    /// ROOT-LAYER: `fee_rate_sat_vb` is the one function every fee reader calls (10 sites, btc_payout, node_runtime,
    /// rpc_http), so the class is closed for all of them at once.
    #[test]
    fn lock_net_io_a_slow_bitcoin_source_never_holds_the_fee_estimate_caller() {
        if std::env::var("MONEROUSD_BTC_FEE_RATE_SAT_VB").is_ok() {
            return; // a fixed rate short-circuits the source; this pin measures the source path
        }
        fee_cache::reset();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a local stand-in for Core");
        let addr = listener.local_addr().expect("its address");
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let mut s = stream;
                    let mut buf = [0u8; 4096];
                    if s.read(&mut buf).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(3_000));
                    let body = r#"{"result":{"feerate":0.00012,"blocks":6},"error":null,"id":"usdmd"}"#;
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    if s.write_all(reply.as_bytes()).is_err() {
                        eprintln!("[lock-net-io pin] the stand-in could not write its answer");
                    }
                });
            }
        });
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(25)).build();
        let src = BtcSource::CoreRpc { url: format!("http://{addr}/"), auth_header: "Basic eDp4".into(), agent };
        let t0 = std::time::Instant::now();
        let first = src.fee_rate_sat_vb();
        let took = t0.elapsed();
        assert!(took < Duration::from_millis(500), "⛔ the caller waited {took:?} on a slow Bitcoin source");
        assert_eq!(first, None, "a cold cache serves no estimate rather than wait for one");
        let t1 = std::time::Instant::now();
        let mut got = None;
        while t1.elapsed() < Duration::from_secs(10) && got.is_none() {
            std::thread::sleep(Duration::from_millis(100));
            let t = std::time::Instant::now();
            got = src.fee_rate_sat_vb();
            assert!(t.elapsed() < Duration::from_millis(500), "⛔ a later read waited on the network too");
        }
        assert_eq!(got, Some(12), "the background fetch's answer (0.00012 BTC/kvB = 12 sat/vB) is served once it lands");
    }

    #[test]
    fn confirmation_counting_is_thorchains_value_over_subsidy_with_a_floor_of_one() {
        assert_eq!(required_confirmations(1), 1);
        assert_eq!(required_confirmations(BTC_BLOCK_SUBSIDY_SATS), 1);
        assert_eq!(required_confirmations(BTC_BLOCK_SUBSIDY_SATS + 1), 2);
        assert_eq!(required_confirmations(BTC_BLOCK_SUBSIDY_SATS * 7), 7);
        let small = ReserveCoin { txid: [0; 32], vout: 0, value_sats: 100_000, confirmations: 1 };
        let whale = ReserveCoin { txid: [0; 32], vout: 0, value_sats: 5 * BTC_BLOCK_SUBSIDY_SATS, confirmations: 4 };
        assert!(small.matured(), "a small coin is final at one confirmation");
        assert!(!whale.matured(), "five subsidies' worth waits for its fifth confirmation");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(net_of_address("bcrt1p26sht9vf09a6x40pdjckgw5fyy6vlr8kx5g7tdtr4mdf6vm96hxqjya5l9"), crate::btc_tx::BtcNet::Regtest);
        assert_eq!(net_of_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), crate::btc_tx::BtcNet::Testnet);
        assert_eq!(net_of_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"), crate::btc_tx::BtcNet::Mainnet);
    }

    #[test]
    fn a_clearnet_core_url_is_refused_and_this_machines_core_is_accepted() {
        // env is process-global: one test holds every arm so no sibling interleaves; and the simulated-Bitcoin slot
        // `btc_source` answers first in a test build is process-global too, so this holds the lock every pin that installs
        // one holds (a sibling's installed world once answered here: "a clearnet Core host is refused" red at 2 threads)
        let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("MONEROUSD_BTC_RPC_URL", "http://198.51.100.7:8332");
        std::env::set_var("MONEROUSD_BTC_RPC_AUTH", "u:p");
        assert!(btc_source(crate::btc_tx::BtcNet::Regtest).is_none(), "a clearnet Core host is refused");
        std::env::set_var("MONEROUSD_BTC_RPC_URL", "http://127.0.0.1:18443");
        assert!(matches!(btc_source(crate::btc_tx::BtcNet::Regtest), Some(BtcSource::CoreRpc { .. })), "this machine's Core is accepted");
        std::env::remove_var("MONEROUSD_BTC_RPC_URL");
        std::env::remove_var("MONEROUSD_BTC_RPC_AUTH");
        assert!(btc_source(crate::btc_tx::BtcNet::Regtest).is_none(), "regtest has no explorer: Core or nothing");
    }

    #[test]
    fn address_network_is_read_from_the_hrp() {
        assert!(is_testnet_address("tb1pxyz"));
        assert!(is_testnet_address(
            "TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX"
        ));
        assert!(!is_testnet_address("bc1pxyz"));
        assert!(!is_testnet_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // The pool is Tor-reachable + testnet4/mainnet-correct; the built-in source is the mempool hidden service.
        let tb = esplora_bases(true);
        assert!(
            tb.iter().all(|b| b.ends_with("/testnet4/api")),
            "testnet pool targets testnet4"
        );
        assert!(
            tb.iter()
                .any(|b| b
                    .contains("mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion")),
            "built-in onion present"
        );
        assert!(
            esplora_bases(false)
                .iter()
                .all(|b| b.ends_with("/api") && !b.contains("testnet")),
            "mainnet pool targets mainnet"
        );
    }

    #[test]
    fn zero_min_never_confirms() {
        // A swap always requires a positive deposit — min_sats == 0 must never authorize a mint.
        assert!(!deposit_confirmed(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            0
        ));
    }

    /// ⭐ MEASURED 2026-11-10 (launch_trade.py round 23, real nodes): two nodes sharing one Core had 836 scans refused as "Scan
    /// already in progress"; each read as an address with no coins, so the payout proposer skipped the reserve with BTC still
    /// owed and both nodes raised a solvency hold. A busy scan answers the address's newest view; an address never read stays
    /// unanswered. Driven against a stand-in Core speaking Core's own JSON-RPC answers.
    #[test]
    fn a_busy_core_scan_answers_the_newest_view_never_an_empty_reserve() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("its address").port();
        let txid = "11".repeat(32);
        let ok = format!(r#"{{"result":{{"height":110,"unspents":[{{"txid":"{txid}","vout":1,"amount":0.0002,"height":100}}]}},"error":null,"id":"usdmd"}}"#);
        let busy = r#"{"result":null,"error":{"code":-8,"message":"Scan already in progress, use action \"abort\" or \"status\""},"id":"usdmd"}"#.to_string();
        let answers = vec![(200, ok), (500, busy.clone()), (500, busy.clone()), (500, busy)];
        let server = std::thread::spawn(move || {
            for (code, body) in answers {
                let Ok((mut s, _)) = listener.accept() else { return };
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req);
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h]
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if req.len() >= h + 4 + len {
                            break;
                        }
                    }
                }
                let reason = if code == 200 { "OK" } else { "Internal Server Error" };
                let _ = write!(s, "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        let src = BtcSource::CoreRpc { url: format!("http://127.0.0.1:{port}/"), auth_header: "Basic dTpw".into(), agent: ureq::AgentBuilder::new().build() };
        let address = "bcrt1qbusyscanpinaddress0000000000000";
        let first = src.utxos(address).expect("a scan Core answers is read");
        assert_eq!((first.len(), first[0].value_sats, first[0].confirmations), (1, 20_000, 11), "the scan reads Core's coin and its depth");
        // the busy answer: the newest view, never an empty reserve
        let again = src.utxos(address).map(|c| c.iter().map(|k| k.value_sats).sum::<u64>());
        assert_eq!(again, Some(20_000), "⛔ a busy Core scan read as an address with no coins");
        // CALIBRATION — the reader this replaces: Core's busy answer itself carries no coins
        assert!(src.core_call("scantxoutset", serde_json::json!(["start", [{ "desc": format!("addr({address})") }]])).is_none(), "CALIBRATION: Core's busy answer holds no coins");
        // an address this node never read: nothing is invented
        assert!(src.utxos("bcrt1qneverreadbusyscanpin00000000000").is_none(), "⛔ a busy scan invented coins for an address never read");
        let _ = server.join();
    }
}

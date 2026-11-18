// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE WALLET'S CONNECT DOOR: A WEBSITE CONNECTS TO THIS WALLET AND TRANSACTS THROUGH IT (user 2026-11-10: "users should
//! be able to connect their wallet directly to the website. in the future itll be offered as a browser plugin wallet";
//! "the wallet should be able to connect and transact on ion.monerousd.org as well").
//!
//! WHAT IT IS, AND WHAT IT IS NOT. A site opened in an ordinary browser on this computer (the official
//! `https://ion.monerousd.org`, or the same pages served by this user's own node on `127.0.0.1:27752` when the official
//! host is down) talks to this wallet through one door on the computer's own loopback address, `127.0.0.1:27751` (the
//! port the earlier desktop proxy and its browser extension used). The door carries REQUESTS between the page and the
//! wallet and nothing else. It never talks to the chain: every transaction is built, proved and broadcast by this
//! wallet through its own node, exactly as a send made inside the wallet is, and every pool, token, NFT and price a
//! page shows is read by this wallet from its own node, which folds the same chain every other node folds. A website's
//! host being up or down changes nothing about either.
//! BORROWED: the loopback bridge of hardware wallets (Trezor Bridge: a local endpoint a web page reaches, gated by
//! origin and by approval on the device; Trezor Connect's popup window as the transport where a page may not reach the
//! endpoint itself), the provider-and-session shape of web3 wallets (EIP-1193 `request`, EIP-1102 connect consent,
//! WalletConnect's approve-then-session), and this project's own earlier extension (`window.monerousd`).
//!
//! TWO WAYS A PAGE REACHES THE DOOR, ONE DOOR. (a) Directly: the page's own `fetch` to this address, where the browser
//! allows a website to reach this computer (Chrome, Edge and Firefox do, after the browser's own permission prompt).
//! (b) Through the BRIDGE WINDOW: a small window the page opens at this door's own `/bridge` page; the page talks to
//! that window with `postMessage`, and the window (same origin as the door, so no browser rule is in the way) passes
//! each request on, stamped with the origin the BROWSER reported for the page. Safari and Brave need (b).
//!
//! THE DOOR IS SHUT UNLESS ITS USER IS CONNECTING A SITE (DIGITAL CASH: a website must not learn that a wallet runs on
//! this computer by knocking). Nothing listens until the user arms it: "Connect a website" in the wallet, or a
//! `monerousd://connect?origin=…` link the site's own Connect button asked the computer to open. Armed, it takes
//! connection requests for a few minutes (from the named origin only, when the link named one). It stays open while at
//! least one site is connected and shuts when the last one ends.
//!
//! WHAT A CONNECTED SITE GETS, BY DEFAULT AND BY GRANT (protections on by default):
//!   - always: the chain's public facts (prices, pools, tokens, collections, heights) read through this wallet's node,
//!     and the right to ASK for an action;
//!   - on connecting: a session name made for that site alone and NO address (an address is a payment endpoint a
//!     site could recognise the wallet by; a site that needs one asks, and the wallet's user approves that as an action),
//!     so two sites cannot recognise the same wallet;
//!   - only by a grant the user approves for that site by name: balances, holdings and activity ("balances"). Until
//!     then those answers are `hidden`, and the page shows them as hidden;
//!   - never, by any grant: letters. Letters travel over the chain and are read and sent in the wallet (user
//!     2026-11-11: "letter is on chain so it can stay in the wallet ... it doesnt need a web app yet"); a website that
//!     asks for one is refused, and there is no prompt a page could talk a user through;
//!   - never without the user's approval of THAT action, in the wallet's own sheet with every cost in dollars and
//!     again in the core: anything that spends, swaps, lists, creates or publishes.
//!
//! WHAT A HOSTILE PAGE MEETS (§9.6 for this door; it admits requests to the WALLET, never bytes into consensus):
//! (1) proof of work: none is at stake; every chain object a request leads to is built and stamped by the wallet's own
//!     existing commands. (2) authority: a request is answered only under a session token (32 random bytes, compared in
//!     constant time) issued to the same origin after the user approved that origin BY NAME in the core's own approval
//!     prompt; a connection request is taken only while the door is armed. The `Host` header must be this loopback
//!     address, so a name re-pointed at 127.0.0.1 (DNS rebinding) is refused. A browser sets `Origin` itself and a
//!     page cannot forge it; the bridge window's word for a page's origin (`X-Dapp-Origin`) is believed ONLY on a
//!     request whose own `Origin` is this door, which no other page can send. A program that is not a browser can
//!     forge either and gains nothing: it still needs a token the user issued, and every action still asks.
//! (3) value: this module moves none; the provider it forwards to asks the user before anything is spent or published.
//! (4) replay: a connection request id is single-use and its token is handed out once; a request is answered once.
//! (5) bounded work: headers at most 16 KiB, a body at most 8 MiB (a collection's pictures), at most `MAX_PENDING`
//!     connection requests, `MAX_SESSIONS` sessions and `MAX_CALLS` requests in flight; past a bound the door answers
//!     "busy" and holds nothing. (6) parity with the framed provider (`wireDappProviderBridge`): the same dispatcher
//!     answers; where the framed door trusts the frame the wallet itself created, this one requires the session, and
//!     where the framed door's private reads rest on one app-wide consent, this one's rest on a grant per site.
//! (7) scale: one user's own computer; nothing here is per node, per block or per chain item.
//! (8) what protects it (AI RESISTANT): WHO MAY ASK is (b), ordinary code: the origin, Host, token and method-table
//!     checks above, pinned by this file's tests. WHAT HAPPENS is never this door's to decide: every chain object a
//!     request leads to is judged by (a), the proofs every node checks, exactly as if the wallet's own page had asked.
//!     The one (c) is the wallet's own user approving an action on their OWN funds; no (c) here can move another
//!     person's funds. PERSUASION GAINS NOTHING: a page can only ask. The site's name and each action's cost in the
//!     approval are built by the core from the request's own arguments and the door's own record of the origin, never
//!     from words the page supplies (its `app` label is shown nowhere in an approval); no request reveals the seed, a
//!     key or an address; and a site that talks its user into approving still gets only the action the sheet named.
//!
//! NOTHING IS KEPT ON DISK: sessions and grants live in this process's memory and end with it.
//!
//! Cons, quantified: while a site is connected, any page the browser lets reach this computer can tell that SOMETHING
//! listens on port 27751 (not what, and it gets no answer without a session); the door is shut at every other time.
//! The bridge window is one extra small window, kept open for the length of the session, in Safari and Brave only.
//! A site the user connects and grants balances to can read those balances for as long as its session lasts: that is
//! the user's own choice, named in the prompt, and ended with one tap.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The loopback port (the earlier desktop proxy's, so the extension's own permission list already names it).
pub const PORT: u16 = 27751;
const ARMED_FOR: Duration = Duration::from_secs(300);
const PENDING_FOR: Duration = Duration::from_secs(300);
const CALL_WAIT: Duration = Duration::from_secs(660);
const MAX_PENDING: usize = 4;
const MAX_SESSIONS: usize = 16;
const MAX_CALLS: usize = 32;
const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;

/// What a provider method is to a website's session. EVERY method the wallet's provider answers is in [`METHODS`]; a
/// method that is not there is refused at this door (the `finished` check keeps the two lists equal).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// a public fact of the chain, read through this wallet's node
    Open,
    /// who the site is talking to: a session name made for this site alone, never an address
    Identity,
    /// this wallet's balances, holdings and activity: answered only under the site's "balances" grant
    Balances,
    /// this wallet's letters, read or sent as the user: never answered to a website (they stay in the wallet)
    Letters,
    /// spends, swaps, lists, creates or publishes: the wallet asks its user every time
    Action,
    /// the site asks for a grant; the wallet shows the request and its user decides
    Grant,
}

pub const METHODS: &[(&str, Kind)] = &[
    ("getNetwork", Kind::Open),
    ("getHeight", Kind::Open),
    ("qrSvg", Kind::Open),
    ("request", Kind::Open),
    ("nodeRpc", Kind::Open),
    ("daemonRpc", Kind::Open),
    ("profileGet", Kind::Open),
    ("nativeAssets", Kind::Open),
    ("autoOpsec", Kind::Open),
    ("nativePools", Kind::Open),
    ("swapQuote", Kind::Open),
    ("ionPools", Kind::Open),
    ("ionPool", Kind::Open),
    ("bookDepth", Kind::Open),
    ("createFee", Kind::Open),
    ("assetCard", Kind::Open),
    ("ladderPreview", Kind::Open),
    ("connect", Kind::Identity),
    ("getAddress", Kind::Identity),
    ("listAddresses", Kind::Identity),
    ("getBalance", Kind::Balances),
    ("assets", Kind::Balances),
    ("noteOwned", Kind::Balances),
    ("cardFor", Kind::Balances),
    ("nativeProgress", Kind::Balances),
    ("collectionProgress", Kind::Balances),
    ("ionPosition", Kind::Balances),
    ("ionOrders", Kind::Balances),
    ("letterAddress", Kind::Letters),
    ("letterInbox", Kind::Letters),
    ("letterHistory", Kind::Letters),
    ("letterSend", Kind::Letters),
    ("newAddress", Kind::Action),
    ("transfer", Kind::Action),
    ("signAndBroadcast", Kind::Action),
    ("claimStakeReward", Kind::Action),
    ("dirRegister", Kind::Action),
    ("profileSet", Kind::Action),
    ("nativeSwap", Kind::Action),
    ("setAutoOpsec", Kind::Action),
    ("createToken", Kind::Action),
    ("createCollection", Kind::Action),
    ("sendAsset", Kind::Action),
    ("dsolCall", Kind::Action),
    ("swapExecute", Kind::Action),
    ("ionAdd", Kind::Action),
    ("ionRemove", Kind::Action),
    // a liquidity lock (user 2026-11-12): moving a position into, out of and back from a lock moves value like ionRemove
    ("ionRemoveLocked", Kind::Action),
    ("ionLock", Kind::Action),
    ("ionUnlock", Kind::Action),
    ("ionBuy", Kind::Action),
    ("ionSell", Kind::Action),
    ("ionLaunch", Kind::Action),
    ("ionClaim", Kind::Action),
    ("ionSwap", Kind::Action),
    ("orderPost", Kind::Action),
    ("ladderPost", Kind::Action),
    ("ladderCancelTargets", Kind::Action),
    ("grant", Kind::Grant),
];

pub fn kind_of(method: &str) -> Option<Kind> {
    METHODS.iter().find(|(m, _)| *m == method).map(|(_, k)| *k)
}

/// The one grant a site can be given, by the words the prompt uses. (Letters are not grantable: see `Kind::Letters`.)
pub fn grant_words(what: &str) -> Option<&'static str> {
    match what {
        "balances" => Some("see your balances, what you hold and your activity"),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Decision {
    Waiting,
    Approved(String),
    Refused,
}

struct Pending {
    origin: String,
    app: String,
    wants_balances: bool,
    decision: Decision,
    asked: Instant,
}

#[derive(Clone, Debug, Default)]
struct Session {
    origin: String,
    /// the name this site knows the session by: random, made when it was approved, the same for no other site
    name: String,
    balances: bool,
}

#[derive(Default)]
struct Bridge {
    listening: bool,
    armed_until: Option<Instant>,
    /// When a link armed the door for one site, only that origin may ask to connect.
    armed_origin: Option<String>,
    pending: HashMap<String, Pending>,
    /// token → the session it opens
    sessions: HashMap<String, Session>,
    /// request id → its answer, once the wallet's page has given one
    answers: HashMap<String, Option<Result<serde_json::Value, String>>>,
}

struct Shared {
    state: Mutex<Bridge>,
    answered: Condvar,
}

fn shared() -> &'static Arc<Shared> {
    static S: OnceLock<Arc<Shared>> = OnceLock::new();
    S.get_or_init(|| Arc::new(Shared { state: Mutex::new(Bridge::default()), answered: Condvar::new() }))
}

type Emitter = Box<dyn Fn(&str, serde_json::Value) + Send + Sync>;
static EMIT: OnceLock<Emitter> = OnceLock::new();

/// Give the bridge its way to reach the wallet's page (set once, at app start).
pub fn set_emitter(f: impl Fn(&str, serde_json::Value) + Send + Sync + 'static) {
    let _ = EMIT.set(Box::new(f));
}

fn emit(event: &str, payload: serde_json::Value) {
    if let Some(f) = EMIT.get() {
        f(event, payload);
    }
}

/// A granted private read, answered by the wallet's core itself: `Some(answer)` when the core answers this method,
/// `None` when the wallet's page does (set once, at app start).
type PrivateRead = fn(&str, &serde_json::Value) -> Option<Result<serde_json::Value, String>>;
static PRIVATE_READ: OnceLock<PrivateRead> = OnceLock::new();

pub fn set_private_reader(f: PrivateRead) {
    let _ = PRIVATE_READ.set(f);
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Equal without a data-dependent early exit (a token is a secret; a page must not learn it byte by byte from timing).
fn same(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn own_origins() -> [String; 2] {
    [format!("http://127.0.0.1:{PORT}"), format!("http://localhost:{PORT}")]
}

/// An origin a browser sends for a page: `https://host[:port]`, or plain http only for this computer's own pages (the
/// node's own site host, a developer's local site). Anything else (`null`, a file page, a browser extension's own
/// scheme until the plugin wallet ships, this door itself) is not a site the user can be shown by name.
pub fn origin_ok(origin: &str) -> bool {
    let o = origin.trim();
    if o.len() > 200 || o.contains(|c: char| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '<' | '>' | '\'' | '@')) {
        return false;
    }
    if own_origins().iter().any(|own| own == o) {
        return false;
    }
    if let Some(host) = o.strip_prefix("https://") {
        return !host.is_empty() && !host.contains('/') && !host.contains('?') && !host.contains('#');
    }
    if let Some(host) = o.strip_prefix("http://") {
        let name = host.split(':').next().unwrap_or("");
        return !host.contains('/') && !host.contains('?') && !host.contains('#') && (name == "127.0.0.1" || name == "localhost");
    }
    false
}

/// WHICH SITE IS ASKING. The browser's own `Origin` header names it. The bridge window's word for it (`X-Dapp-Origin`)
/// is believed only on a request whose own `Origin` is this door's, which only this door's own page can send: any
/// other page that sets that header still arrives under its own origin, and is taken as that origin.
pub fn site_of(origin_header: &str, dapp_origin_header: &str) -> Option<String> {
    let site = if own_origins().iter().any(|own| own == origin_header) { dapp_origin_header } else { origin_header };
    origin_ok(site).then(|| site.trim().to_string())
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
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

fn link_field(link: &str, head: &str, field: &str) -> Option<String> {
    let rest = link.trim().strip_prefix(head)?;
    let query = rest.strip_prefix('?')?;
    let key = format!("{field}=");
    let raw = query.split('&').find_map(|kv| kv.strip_prefix(key.as_str()))?;
    percent_decode(raw)
}

/// The origin a `monerousd://connect?origin=…` link names, when it is one a browser could send.
pub fn link_origin(link: &str) -> Option<String> {
    let o = link_field(link, "monerousd://connect", "origin")?;
    origin_ok(&o).then_some(o)
}

/// The page a `monerousd://browse?url=…` link names (a phone's browser handing a site to the wallet's own browser): an
/// https page, or one of this device's own.
pub fn link_browse(link: &str) -> Option<String> {
    let u = link_field(link, "monerousd://browse", "url")?;
    let origin_end = u.find("://").map(|i| u[i + 3..].find('/').map(|j| i + 3 + j).unwrap_or(u.len()))?;
    (u.len() <= 2048 && !u.contains(|c: char| c.is_whitespace() || c.is_control()) && origin_ok(&u[..origin_end])).then_some(u)
}

/// ARM THE DOOR: its user is connecting a site. `for_origin`: the one site a link named, or `None` when the user pressed
/// "Connect a website" in the wallet (any site may then ask, and the user sees which one did). Starts the listener if it
/// is not running. `Err` when the port cannot be bound (another program holds it).
pub fn arm(for_origin: Option<String>) -> Result<(), String> {
    let s = shared();
    let start = {
        let mut g = s.state.lock().unwrap_or_else(|e| e.into_inner());
        g.armed_until = Some(Instant::now() + ARMED_FOR);
        g.armed_origin = for_origin;
        !g.listening
    };
    if start {
        // Loopback ONLY: bound to 127.0.0.1, never a routable interface; the client is a browser on this same computer.
        let listener = TcpListener::bind(("127.0.0.1", PORT)).map_err(|e| format!("the connect door could not open on this computer (port {PORT}): {e}"))?;
        s.state.lock().unwrap_or_else(|e| e.into_inner()).listening = true;
        let shared = Arc::clone(s);
        std::thread::spawn(move || serve(listener, shared));
    }
    Ok(())
}

/// The site a waiting connection request names, and whether it asked to see balances: what the core's approval prompt
/// is built from (never from what a caller passes in).
pub fn waiting_site(request: &str) -> Option<(String, bool)> {
    let g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    g.pending.get(request).filter(|p| p.decision == Decision::Waiting).map(|p| (p.origin.clone(), p.wants_balances))
}

/// Every connection request still waiting for its user: `(request, site, app name, asks for balances)`. For a wallet
/// page that opened after the request arrived (the app was started BY the site's link).
pub fn waiting() -> Vec<(String, String, String, bool)> {
    let mut g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    wanted(&mut g);
    g.pending.iter().filter(|(_, p)| p.decision == Decision::Waiting).map(|(id, p)| (id.clone(), p.origin.clone(), p.app.clone(), p.wants_balances)).collect()
}

/// The user's answer to a connection request. `approved`: whether the site may see balances; `None` refuses. The
/// CALLER has already put the approval to the user in the core's own prompt.
pub fn decide(request: &str, approved: Option<bool>) -> Result<String, String> {
    decide_in(shared(), request, approved)
}

fn decide_in(s: &Shared, request: &str, approved: Option<bool>) -> Result<String, String> {
    let mut g = s.state.lock().unwrap_or_else(|e| e.into_inner());
    if approved.is_some() && g.sessions.len() >= MAX_SESSIONS {
        return Err("too many sites are connected: end one first".into());
    }
    let p = g.pending.get_mut(request).ok_or("that connection request is no longer waiting")?;
    if p.decision != Decision::Waiting {
        return Err("that connection request was already answered".into());
    }
    let origin = p.origin.clone();
    match approved {
        Some(balances) => {
            let token = random_hex(32);
            p.decision = Decision::Approved(token.clone());
            g.sessions.insert(token, Session { origin: origin.clone(), name: random_hex(8), balances });
        }
        None => p.decision = Decision::Refused,
    }
    Ok(origin)
}

/// Is this site connected now.
pub fn is_connected(origin: &str) -> bool {
    shared().state.lock().unwrap_or_else(|e| e.into_inner()).sessions.values().any(|s| s.origin == origin)
}

/// Does this site hold this grant now.
pub fn holds(origin: &str, what: &str) -> bool {
    let g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.values().any(|s| s.origin == origin && what == "balances" && s.balances)
}

/// Give (or take back) a grant on every session of one site. The CALLER has already put a giving to the user in the
/// core's own prompt, naming the site and the grant.
pub fn set_grant(origin: &str, what: &str, on: bool) -> Result<(), String> {
    set_grant_in(shared(), origin, what, on)
}

fn set_grant_in(s: &Shared, origin: &str, what: &str, on: bool) -> Result<(), String> {
    grant_words(what).ok_or("there is no such grant")?;
    let mut g = s.state.lock().unwrap_or_else(|e| e.into_inner());
    let mut any = false;
    for sess in g.sessions.values_mut().filter(|sess| sess.origin == origin) {
        any = true;
        sess.balances = on;
    }
    if any {
        Ok(())
    } else {
        Err("that site is not connected".into())
    }
}

/// The wallet page's answer to one provider request.
pub fn respond(id: &str, answer: Result<serde_json::Value, String>) {
    let s = shared();
    let mut g = s.state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = g.answers.get_mut(id) {
        *slot = Some(answer);
        s.answered.notify_all();
    }
}

/// The sites linked now, for the wallet's own list: `(site, sees balances)`.
pub fn linked_sites() -> Vec<(String, bool)> {
    let g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    let mut by_site: HashMap<&str, bool> = HashMap::new();
    for s in g.sessions.values() {
        *by_site.entry(s.origin.as_str()).or_insert(false) |= s.balances;
    }
    let mut v: Vec<(String, bool)> = by_site.into_iter().map(|(o, b)| (o.to_string(), b)).collect();
    v.sort();
    v
}

/// End every session of one site (the user's tap in the wallet).
pub fn end(origin: &str) {
    let mut g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.retain(|_, s| s.origin != origin);
}

/// End everything: every session, every waiting request, the armed window (the wallet was locked or closed).
pub fn end_all() {
    let mut g = shared().state.lock().unwrap_or_else(|e| e.into_inner());
    g.sessions.clear();
    g.pending.clear();
    g.armed_until = None;
    g.armed_origin = None;
}

/// Is anything keeping the door open: an armed window, a request the user has not answered, or a linked site.
fn wanted(g: &mut Bridge) -> bool {
    let now = Instant::now();
    if g.armed_until.is_some_and(|t| t <= now) {
        g.armed_until = None;
        g.armed_origin = None;
    }
    g.pending.retain(|_, p| now.duration_since(p.asked) < PENDING_FOR);
    g.armed_until.is_some() || !g.pending.is_empty() || !g.sessions.is_empty()
}

fn serve(listener: TcpListener, shared: Arc<Shared>) {
    // a non-blocking accept lets the door notice that nobody wants it open any more, and shut
    let _ = listener.set_nonblocking(true);
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue; // bound to loopback, so this cannot happen; refused all the same
                }
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                    handle(stream, &shared);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
                if !wanted(&mut g) {
                    g.listening = false;
                    return; // dropping the listener shuts the door
                }
                drop(g);
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(150)),
        }
    }
}

struct Request {
    method: String,
    route: String,
    origin: String,
    dapp_origin: String,
    host: String,
    bearer: String,
    body: Vec<u8>,
}

fn take_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEADER {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).ok()?.to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, route) = (first.next()?.to_string(), first.next()?.to_string());
    let (mut origin, mut dapp_origin, mut host, mut bearer, mut length) = (String::new(), String::new(), String::new(), String::new(), 0usize);
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "origin" => origin = v.to_string(),
            "x-dapp-origin" => dapp_origin = v.to_string(),
            "host" => host = v.to_string(),
            "authorization" => bearer = v.strip_prefix("Bearer ").unwrap_or("").to_string(),
            "content-length" => length = v.parse().ok()?,
            _ => {}
        }
    }
    if length > MAX_BODY {
        return None;
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Some(Request { method, route, origin, dapp_origin, host, bearer, body })
}

/// Send every byte of an answer down the socket to the browser (a socket send; nothing touches a disk).
fn send(stream: &mut TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) | Err(_) => return,
            Ok(n) => bytes = &bytes[n..],
        }
    }
    let _ = stream.flush();
}

fn answer(stream: &mut TcpStream, status: &str, origin_header: &str, body: &serde_json::Value) {
    let text = body.to_string();
    // the answer is readable only by the origin that asked, and only when that origin is one a user can be shown
    let cors = if origin_ok(origin_header) {
        format!(
            "Access-Control-Allow-Origin: {origin_header}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type, authorization\r\nAccess-Control-Allow-Private-Network: true\r\nAccess-Control-Max-Age: 600\r\n"
        )
    } else {
        String::new()
    };
    let head = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n{cors}Content-Length: {}\r\nConnection: close\r\n\r\n", text.len());
    send(stream, head.as_bytes());
    send(stream, text.as_bytes());
}

/// THE BRIDGE WINDOW: the door's own page, opened by a site as a small window. It takes requests from the window that
/// opened it (and from no other), pins that window's origin as the browser reported it on the first message, and
/// passes each request to the door under that origin. It holds no secret of its own and shows the site's name. Its
/// headline is whatever the door last answered (waiting, approved, not answering), never a fixed word.
const BRIDGE_PAGE: &str = r##"<!doctype html><html><head><meta charset="utf-8"><title>MoneroUSD wallet link</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:15px/1.5 -apple-system,system-ui,sans-serif;background:#0d0f14;color:#e8eaf0;margin:0;padding:26px}
h1{font-size:17px;margin:0 0 12px}p{color:#aab0c0;margin:8px 0}.site{color:#fff;font-weight:600;word-break:break-all}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#f5a524;margin-right:8px}.on .dot{background:#2ecc71}</style></head>
<body><h1><span class="dot"></span><span id="t"></span></h1>
<p>Site: <span class="site" id="s"></span></p>
<p>This window carries requests between that site and the MoneroUSD wallet on this computer. Keep it open while you use the site. Closing it ends the link. Nothing moves without your approval in the wallet.</p>
<script>
(function () {
  var site = null, op = window.opener;
  var SAID = { waiting: 'Waiting for the site', ask: 'Approve in your wallet', approved: 'The wallet approved this site', gone: 'The wallet is not answering', none: 'Open this from a site’s Connect button' };
  function say(k, on) { document.getElementById('t').textContent = SAID[k]; document.body.className = on ? 'on' : ''; }
  say('waiting');
  document.getElementById('s').textContent = 'not named yet';
  if (!op) { say('none'); return; }
  var ROUTES = { '/connect': 1, '/session': 1, '/rpc': 1, '/disconnect': 1 };
  var linked = false;
  window.addEventListener('message', function (ev) {
    if (ev.source !== op) return;
    var d = ev.data;
    if (!d || d.type !== 'monerousd:door' || !ROUTES[d.route]) return;
    if (site === null) { site = ev.origin; document.getElementById('s').textContent = site; say('ask'); }
    if (ev.origin !== site) return;
    var h = { 'Content-Type': 'application/json', 'X-Dapp-Origin': site };
    if (d.token) h.Authorization = 'Bearer ' + d.token;
    fetch(d.route, { method: 'POST', headers: h, body: JSON.stringify(d.body || {}), cache: 'no-store' })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, body: j }; }); })
      .catch(function () { return { status: 0, body: {} }; })
      .then(function (a) {
        if (a.body && a.body.status === 'approved') linked = true;
        if (a.status === 401) linked = false;
        if (a.status === 0) say('gone'); else say(linked ? 'approved' : 'ask', linked);
        try { op.postMessage({ type: 'monerousd:door-res', id: d.id, status: a.status, body: a.body }, site); } catch (e) { /* the site is gone */ }
      });
  });
  try { op.postMessage({ type: 'monerousd:door-ready' }, '*'); } catch (e) { /* no opener to tell */ }
  setInterval(function () { try { if (op.closed) window.close(); } catch (e) { /* cannot tell: stay */ } }, 1500);
})();
</script></body></html>"##;

fn answer_page(stream: &mut TcpStream) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BRIDGE_PAGE.len()
    );
    send(stream, head.as_bytes());
    send(stream, BRIDGE_PAGE.as_bytes());
}

fn handle(mut stream: TcpStream, shared: &Arc<Shared>) {
    let Some(req) = take_request(&mut stream) else {
        return;
    };
    // a name re-pointed at this computer is not this door
    if req.host != format!("127.0.0.1:{PORT}") && req.host != format!("localhost:{PORT}") {
        return answer(&mut stream, "403 Forbidden", "", &serde_json::json!({ "error": "not this door" }));
    }
    if req.method == "GET" && req.route.split(['?', '#']).next() == Some("/bridge") {
        return answer_page(&mut stream);
    }
    let Some(site) = site_of(&req.origin, &req.dapp_origin) else {
        return answer(&mut stream, "403 Forbidden", "", &serde_json::json!({ "error": "no site named" }));
    };
    if req.method == "OPTIONS" {
        return answer(&mut stream, "200 OK", &req.origin, &serde_json::json!({})); // the browser's preflight
    }
    if req.method != "POST" {
        return answer(&mut stream, "405 Method Not Allowed", &req.origin, &serde_json::json!({ "error": "POST only" }));
    }
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
    let (status, reply) = match req.route.as_str() {
        "/connect" => connect(shared, &site, &body),
        "/session" => session(shared, &site, &body),
        "/rpc" => rpc(shared, &site, &req.bearer, &body),
        "/disconnect" => {
            let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            let key = g.sessions.iter().find(|(t, s)| same(t, &req.bearer) && s.origin == site).map(|(t, _)| t.clone());
            if let Some(t) = key {
                g.sessions.remove(&t);
            }
            ("200 OK", serde_json::json!({ "ok": true }))
        }
        _ => ("404 Not Found", serde_json::json!({ "error": "no such call" })),
    };
    answer(&mut stream, status, &req.origin, &reply);
}

fn connect(shared: &Arc<Shared>, origin: &str, body: &serde_json::Value) -> (&'static str, serde_json::Value) {
    let app: String = body.get("app").and_then(|a| a.as_str()).unwrap_or("").chars().filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '"' | '&')).take(80).collect();
    let wants_balances = body.get("balances").and_then(|b| b.as_bool()).unwrap_or(false);
    let id = {
        let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
        wanted(&mut g);
        if g.armed_until.is_none() || g.armed_origin.as_ref().is_some_and(|o| o != origin) {
            return ("403 Forbidden", serde_json::json!({ "error": "the wallet is not connecting a site right now" }));
        }
        // one waiting request per site: asking again returns the one already shown
        if let Some((id, _)) = g.pending.iter().find(|(_, p)| p.origin == origin && p.decision == Decision::Waiting) {
            return ("200 OK", serde_json::json!({ "request": id }));
        }
        if g.pending.len() >= MAX_PENDING {
            return ("429 Too Many Requests", serde_json::json!({ "error": "busy" }));
        }
        let id = random_hex(16);
        g.pending.insert(id.clone(), Pending { origin: origin.to_string(), app: app.clone(), wants_balances, decision: Decision::Waiting, asked: Instant::now() });
        id
    };
    emit("web3:connect-request", serde_json::json!({ "request": id, "origin": origin, "app": app, "balances": wants_balances, "front": true }));
    ("200 OK", serde_json::json!({ "request": id }))
}

fn session(shared: &Arc<Shared>, origin: &str, body: &serde_json::Value) -> (&'static str, serde_json::Value) {
    let id = body.get("request").and_then(|r| r.as_str()).unwrap_or("");
    let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    wanted(&mut g);
    let Some(p) = g.pending.get(id) else {
        return ("404 Not Found", serde_json::json!({ "status": "expired" }));
    };
    if p.origin != origin {
        return ("404 Not Found", serde_json::json!({ "status": "expired" }));
    }
    match p.decision.clone() {
        Decision::Waiting => ("200 OK", serde_json::json!({ "status": "pending" })),
        Decision::Refused => {
            g.pending.remove(id);
            ("200 OK", serde_json::json!({ "status": "refused" }))
        }
        Decision::Approved(token) => {
            g.pending.remove(id); // the token is handed out once
            let s = g.sessions.get(&token).cloned().unwrap_or_default();
            ("200 OK", serde_json::json!({ "status": "approved", "token": token, "session": s.name, "balances": s.balances }))
        }
    }
}

fn refused(error: impl Into<String>) -> (&'static str, serde_json::Value) {
    ("200 OK", serde_json::json!({ "ok": false, "error": error.into() }))
}

/// What a site is told when it asks for something it has not been granted: a plain word the page shows as "hidden".
fn hidden(what: &str) -> (&'static str, serde_json::Value) {
    ("200 OK", serde_json::json!({ "ok": false, "hidden": what, "error": format!("HIDDEN: this site has not been allowed to {}", grant_words(what).unwrap_or("see that")) }))
}

fn rpc(shared: &Arc<Shared>, origin: &str, bearer: &str, body: &serde_json::Value) -> (&'static str, serde_json::Value) {
    let method: String = body.get("method").and_then(|m| m.as_str()).unwrap_or("").chars().filter(|c| c.is_ascii_alphanumeric()).take(48).collect();
    let params = body.get("params").cloned().unwrap_or(serde_json::json!({}));
    let sess = {
        let g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
        match g.sessions.iter().find(|(t, s)| !bearer.is_empty() && same(t, bearer) && s.origin == origin) {
            Some((_, s)) => s.clone(),
            None => return ("401 Unauthorized", serde_json::json!({ "ok": false, "error": "this site is not connected" })),
        }
    };
    let Some(kind) = kind_of(&method) else {
        return refused(format!("this wallet does not answer `{method}`"));
    };
    match kind {
        // who the site is talking to, from the session itself: a name, no address, nothing of the wallet is read
        Kind::Identity => {
            let v = serde_json::json!({ "session": sess.name, "address": "", "addresses": [], "balances": sess.balances });
            return ("200 OK", serde_json::json!({ "ok": true, "result": v }));
        }
        Kind::Balances if !sess.balances => return hidden("balances"),
        Kind::Letters => return refused("letters are read and sent in your wallet, never by a website"),
        Kind::Grant if grant_words(params.get("what").and_then(|w| w.as_str()).unwrap_or("")).is_none() => return refused("there is no such grant"),
        _ => {}
    }
    // a granted private read is answered by the wallet's core itself, under this site's own grant
    if kind == Kind::Balances {
        if let Some(r) = PRIVATE_READ.get().and_then(|read| read(&method, &params)) {
            return match r {
                Ok(v) => ("200 OK", serde_json::json!({ "ok": true, "result": v })),
                Err(e) => refused(e),
            };
        }
    }
    let id = {
        let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if g.answers.len() >= MAX_CALLS {
            return ("429 Too Many Requests", serde_json::json!({ "ok": false, "error": "busy" }));
        }
        let id = random_hex(12);
        g.answers.insert(id.clone(), None);
        id
    };
    // an action or a grant waits on the user: the wallet's window comes to the front for it
    let front = matches!(kind, Kind::Action | Kind::Grant);
    emit("web3:request", serde_json::json!({ "id": id, "origin": origin, "method": method, "params": params, "front": front, "balances": sess.balances }));
    let deadline = Instant::now() + CALL_WAIT;
    let mut g = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if let Some(Some(_)) = g.answers.get(&id) {
            break;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        g = shared.answered.wait_timeout(g, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
    }
    match g.answers.remove(&id).flatten() {
        Some(Ok(v)) => ("200 OK", serde_json::json!({ "ok": true, "result": v })),
        Some(Err(e)) => refused(e),
        None => refused("your wallet did not answer in time"),
    }
}

#[cfg(test)]
mod web3_bridge_tests {
    use super::*;

    fn fixture() -> Arc<Shared> {
        Arc::new(Shared { state: Mutex::new(Bridge::default()), answered: Condvar::new() })
    }

    fn armed(s: &Shared, only: Option<&str>) {
        let mut g = s.state.lock().unwrap();
        g.armed_until = Some(Instant::now() + ARMED_FOR);
        g.armed_origin = only.map(str::to_string);
    }

    /// Link `site` and return its token: the door's own steps, with the user's approval given.
    fn linked_site(s: &Arc<Shared>, site: &str, balances: bool) -> String {
        armed(s, None);
        let id = connect(s, site, &serde_json::json!({})).1["request"].as_str().unwrap().to_string();
        decide_in(s, &id, Some(balances)).unwrap();
        session(s, site, &serde_json::json!({ "request": id })).1["token"].as_str().unwrap().to_string()
    }

    /// Only an origin a user can be shown by name is a site: https anywhere, plain http only for this computer's own
    /// pages. A page with no origin, a file page, a name with a path or with characters that could dress up a prompt,
    /// and this door's own origin are each refused.
    #[test]
    fn only_a_site_a_user_can_be_shown_by_name_is_an_origin() {
        let good = ["https://ion.monerousd.org", "https://example.com:8443", "http://127.0.0.1:27752", "http://localhost:5173"];
        for o in good {
            assert!(origin_ok(o), "{o} is a site");
        }
        let own = format!("http://127.0.0.1:{PORT}");
        let bad = [
            "",
            "null",
            "file://",
            "http://example.com",
            "https://",
            "https://a.example/path",
            "https://a.example?x",
            "https://a.example\"><b>x",
            "https://a b.example",
            "https://ion.monerousd.org@evil.example",
            "chrome-extension://abcdef",
            "http://127.0.0.1.evil.example",
            own.as_str(),
        ];
        for o in bad {
            assert!(!origin_ok(o), "{o:?} was taken as a site");
        }
    }

    /// THE BRIDGE WINDOW'S WORD IS BELIEVED ONLY FROM THE BRIDGE WINDOW. A hostile page that sets `X-Dapp-Origin` to
    /// the official site still arrives under its own origin (the browser sets `Origin`, a page cannot), and is taken as
    /// itself; the door's own page is the only sender whose word names another site.
    #[test]
    fn a_page_cannot_name_itself_another_site_through_the_bridge_header() {
        let own = format!("http://127.0.0.1:{PORT}");
        assert_eq!(site_of("https://evil.example", "https://ion.monerousd.org").as_deref(), Some("https://evil.example"), "a page named itself another site");
        assert_eq!(site_of(&own, "https://ion.monerousd.org").as_deref(), Some("https://ion.monerousd.org"));
        assert_eq!(site_of(&format!("http://localhost:{PORT}"), "http://127.0.0.1:27752").as_deref(), Some("http://127.0.0.1:27752"));
        // no origin at all (a program that is not a browser, a plain navigation) names no site
        assert_eq!(site_of("", "https://ion.monerousd.org"), None, "a request with no origin named a site by header alone");
        assert_eq!(site_of(&own, ""), None);
        assert_eq!(site_of(&own, "javascript:alert(1)"), None);
        assert_eq!(site_of(&own, &own), None, "the door took itself for a site");
    }

    /// A connect link names its site and a browse link names its page; a link that is neither, or names something that
    /// is not a site, arms and opens nothing.
    #[test]
    fn a_link_names_one_site_or_nothing() {
        assert_eq!(link_origin("monerousd://connect?origin=https%3A%2F%2Fion.monerousd.org").as_deref(), Some("https://ion.monerousd.org"));
        assert_eq!(link_origin("monerousd://connect?x=1&origin=http%3A%2F%2F127.0.0.1%3A8793").as_deref(), Some("http://127.0.0.1:8793"));
        let none = ["monerousd:pay?to=abc", "monerousd://connect", "monerousd://connect?origin=", "monerousd://connect?origin=javascript%3Aalert(1)", "monerousd://connect?origin=https%3A%2F%2Fa%2Fb", "monerousd://connect?origin=%zz"];
        for l in none {
            assert_eq!(link_origin(l), None, "{l} armed a site");
        }
        assert_eq!(link_browse("monerousd://browse?url=https%3A%2F%2Fion.monerousd.org%2F%23%2Fswap").as_deref(), Some("https://ion.monerousd.org/#/swap"));
        let none = ["monerousd://browse?url=file%3A%2F%2F%2Fetc%2Fpasswd", "monerousd://browse?url=javascript%3Aalert(1)", "monerousd://browse?url=http%3A%2F%2Fexample.com%2F", "monerousd://browse", "monerousd://connect?url=https%3A%2F%2Fa.example%2F"];
        for l in none {
            assert_eq!(link_browse(l), None, "{l} opened a page");
        }
    }

    /// The whole life of a link, on the state alone: a site cannot ask while the door is not armed; armed for one
    /// site, another site cannot ask; a request is shown once however often the site asks; approved hands the token out
    /// exactly once, to that site only; a call needs that token AND that origin; ending the site ends its calls.
    /// TWO-PARTY-REVIEWED: the two parties are two SITES against one wallet's door (the honest site and a hostile one).
    #[test]
    fn a_site_gets_a_session_only_by_the_users_approval_and_only_for_itself() {
        let s = fixture();
        let (a, b) = ("https://ion.monerousd.org", "https://evil.example");
        // not armed: nobody may ask
        assert_eq!(connect(&s, a, &serde_json::json!({})).0, "403 Forbidden");
        armed(&s, Some(a));
        assert_eq!(connect(&s, b, &serde_json::json!({})).0, "403 Forbidden", "another site asked through a door armed for one");
        let (st, r) = connect(&s, a, &serde_json::json!({ "app": "IonSwap" }));
        assert_eq!(st, "200 OK");
        let id = r["request"].as_str().unwrap().to_string();
        assert_eq!(connect(&s, a, &serde_json::json!({})).1["request"].as_str(), Some(id.as_str()), "asking again shows no second request");
        assert_eq!(session(&s, a, &serde_json::json!({ "request": id })).1["status"], "pending");
        assert_eq!(session(&s, b, &serde_json::json!({ "request": id })).1["status"], "expired", "another site read this site's request");
        // the user approves
        assert_eq!(decide_in(&s, &id, Some(false)).as_deref(), Ok(a));
        assert!(decide_in(&s, &id, Some(true)).is_err(), "one request was answered twice");
        let got = session(&s, a, &serde_json::json!({ "request": id })).1;
        let token = got["token"].as_str().unwrap().to_string();
        let name = got["session"].as_str().unwrap().to_string();
        assert_eq!((got["status"].as_str(), name.len()), (Some("approved"), 16));
        assert_eq!(session(&s, a, &serde_json::json!({ "request": id })).1["status"], "expired", "the token was handed out twice");
        // a call needs the token and the origin it was issued to
        let who = serde_json::json!({ "method": "getAddress" });
        assert_eq!(rpc(&s, b, &token, &who).0, "401 Unauthorized", "another site used this site's token");
        assert_eq!(rpc(&s, a, "", &who).0, "401 Unauthorized");
        assert_eq!(rpc(&s, a, &random_hex(32), &who).0, "401 Unauthorized", "a guessed token was taken");
        let me = rpc(&s, a, &token, &who).1;
        assert_eq!((me["result"]["session"].as_str(), me["result"]["address"].as_str()), (Some(name.as_str()), Some("")), "a site was told more than its session's name");
        // the user ends the site: its token no longer answers
        s.state.lock().unwrap().sessions.retain(|_, sess| sess.origin != a);
        assert_eq!(rpc(&s, a, &token, &who).0, "401 Unauthorized", "an ended site still called");
        // and with nothing armed, pending or linked, the door is not wanted open
        {
            let mut g = s.state.lock().unwrap();
            g.armed_until = None;
            assert!(!wanted(&mut g), "the door stays open with nobody to serve");
        }
    }

    /// PROTECTIONS ON BY DEFAULT. A linked site with no grant reads no balance, holding, activity or letter: each
    /// such method answers `hidden` at the door and nothing is asked of the wallet. A grant given to one site opens
    /// that site alone; a method the table does not hold is refused.
    /// TWO-PARTY-REVIEWED: two SITES against one wallet's door; the grant of one must not open the other.
    #[test]
    fn a_site_reads_nothing_private_without_its_own_grant() {
        let s = fixture();
        let (a, b) = ("https://ion.monerousd.org", "https://other.example");
        let ta = linked_site(&s, a, false);
        let tb = linked_site(&s, b, false);
        let private = ["getBalance", "assets", "noteOwned", "cardFor", "nativeProgress", "collectionProgress", "ionPosition", "ionOrders"];
        for m in private {
            let r = rpc(&s, a, &ta, &serde_json::json!({ "method": m })).1;
            assert_eq!((r["ok"].as_bool(), r["hidden"].as_str()), (Some(false), Some("balances")), "{m} answered a site with no grant");
        }
        // letters stay in the wallet: no grant opens them to a website, and nobody can be asked for one
        let letters = ["letterAddress", "letterInbox", "letterHistory", "letterSend"];
        assert!(set_grant_in(&s, a, "letters", true).is_err(), "a website was granted letters");
        for m in letters {
            let r = rpc(&s, a, &ta, &serde_json::json!({ "method": m })).1;
            assert!(r["ok"] == false && r["error"].as_str().unwrap().contains("in your wallet"), "{m} answered a website");
        }
        assert_eq!(rpc(&s, a, &ta, &serde_json::json!({ "method": "grant", "params": { "what": "letters" } })).1["ok"], false, "a website could ask for letters");
        assert!(s.state.lock().unwrap().answers.is_empty(), "a hidden read was passed on to the wallet");
        // each site knows the wallet by a different name and by no address, and one site's grant is its own
        let (na, nb) = (rpc(&s, a, &ta, &serde_json::json!({ "method": "connect" })).1, rpc(&s, b, &tb, &serde_json::json!({ "method": "connect" })).1);
        assert!(na["result"]["session"] != nb["result"]["session"], "two sites were given one name for the wallet");
        assert_eq!((na["result"]["address"].as_str(), nb["result"]["addresses"].as_array().map(Vec::len)), (Some(""), Some(0)), "a site was handed an address by connecting");
        set_grant_in(&s, a, "balances", true).unwrap();
        assert_eq!(rpc(&s, b, &tb, &serde_json::json!({ "method": "getBalance" })).1["hidden"], "balances", "one site's grant opened another site");
        assert!(set_grant_in(&s, "https://nobody.example", "balances", true).is_err(), "a grant was given to a site that is not linked");
        assert!(set_grant_in(&s, a, "everything", true).is_err());
        // a method outside the table, and a grant that does not exist, are refused at the door
        let odd = rpc(&s, a, &ta, &serde_json::json!({ "method": "exportSeed" })).1;
        assert!(odd["ok"] == false && odd["error"].as_str().unwrap().contains("does not answer"), "an unknown method was passed on");
        assert_eq!(rpc(&s, a, &ta, &serde_json::json!({ "method": "grant", "params": { "what": "seed" } })).1["ok"], false);
        assert!(s.state.lock().unwrap().answers.is_empty());
    }

    /// EVERY METHOD HAS ONE KIND, and the methods that move or publish are never open: the table is the door's whole
    /// policy, so a duplicate or a misfiled action is a hole.
    #[test]
    fn the_method_table_files_each_method_once_and_no_action_as_open() {
        let mut seen = std::collections::HashSet::new();
        for (m, _) in METHODS {
            assert!(seen.insert(*m), "{m} is filed twice");
        }
        let acts = ["newAddress", "transfer", "signAndBroadcast", "nativeSwap", "swapExecute", "sendAsset", "createToken", "createCollection", "orderPost", "ladderPost", "ladderCancelTargets", "dsolCall", "dirRegister", "profileSet", "setAutoOpsec", "claimStakeReward"];
        for m in acts {
            assert_eq!(kind_of(m), Some(Kind::Action), "{m} is not filed as an action");
        }
        assert_eq!(kind_of("getBalance"), Some(Kind::Balances));
        assert_eq!(kind_of("letterSend"), Some(Kind::Letters));
        assert_eq!(kind_of("nope"), None);
    }

    /// A refused request yields no session, and a secret is compared without an early exit on its first differing byte.
    #[test]
    fn a_refusal_yields_nothing_and_tokens_compare_in_full() {
        let s = fixture();
        let a = "https://ion.monerousd.org";
        armed(&s, None);
        let id = connect(&s, a, &serde_json::json!({})).1["request"].as_str().unwrap().to_string();
        assert_eq!(decide_in(&s, &id, None).as_deref(), Ok(a));
        assert_eq!(session(&s, a, &serde_json::json!({ "request": id })).1["status"], "refused");
        assert!(s.state.lock().unwrap().sessions.is_empty(), "a refusal left a session behind");
        assert!(same("abcd", "abcd") && !same("abcd", "abce") && !same("abcd", "abc") && !same("", "a"));
    }
}

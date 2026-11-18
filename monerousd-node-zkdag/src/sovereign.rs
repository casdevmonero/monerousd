// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Sovereign hosting server — the LIVE loopback HTTP surface that serves the chain-anchored site
//! bundles ([`crate::site`]) to a same-machine client (the desktop wallet's dApp browser / Ion Swap
//! launcher, an ordinary browser). This is the greenfield realization of Pillar C ("the node is the
//! deploy location for every ecosystem service"): every dApp (Ion Swap, Explorer, MonerousD.org,
//! USDm Pay, IDE, installers) is served FROM THE USER'S OWN NODE, not a central VPS.
//!
//! ## Shape (why it is private + uncensorable by construction)
//! * **Loopback ONLY.** Binds `127.0.0.1:27752` — never a routable interface. The client is on the
//!   same machine (the bundled node under the wallet), so the click never touches the network: no
//!   operator learns which dApp the user opened. The P2P MESH that DISTRIBUTES bundles is onion-only
//!   ([`crate::net`]); this loopback surface is the last hop to the local UI.
//! * **Merkle-anchored.** Each asset is served from a [`crate::site::SiteBundle`] whose root is what a
//!   `SitePublish` anchors on-chain. The server self-verifies every asset with
//!   [`crate::site::verify_served`] against that root before returning it (defense-in-depth: a corrupt
//!   local store is caught fail-closed) and exposes the root in `X-MonerousD-Site-Root` so a client
//!   can independently authenticate the bytes against consensus — trust the root, not the server.
//! * **No phone-home.** A strict `Content-Security-Policy` (`default-src 'self'`, no external hosts)
//!   plus `Referrer-Policy: no-referrer` mean a served page cannot beacon out or leak the user's
//!   interest, address, or amount to anyone.
//!
//! Because ANY node holding the bundle can serve it and the client verifies against the chain root,
//! one surviving honest node serves the whole ecosystem — availability equals the chain's.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::hash::Hash32;
use crate::site::{self, Asset, ServedAsset, SiteBundle, SiteError};

/// The sovereign server binds loopback ONLY — a same-machine private surface, never routable.
pub const SOVEREIGN_LOOPBACK_HOST: &str = "127.0.0.1";
/// Default loopback sovereign HTTP port (the wallet's dApp browser + Ion Swap launcher probe here).
pub const SOVEREIGN_DEFAULT_PORT: u16 = 27752;

/// One hosted site: its sovereign-server directory key (e.g. `ionswap-monerousd-org`) + the
/// chain-anchored bundle the node holds + its content root.
pub struct HostedSite {
    pub dir: String,
    pub bundle: SiteBundle,
    pub root: Hash32,
    /// For a site loaded from the node's site folder: every file's (length, modified time) when it was read, so a request
    /// can tell the folder changed under it. `None` for a site hosted from anywhere else (it is never reloaded from disk).
    pub stamps: Option<HashMap<String, FileStamp>>,
}

/// A file's length and modified time: what changes when a deploy or a checkout writes the file.
pub type FileStamp = (u64, Option<std::time::SystemTime>);

/// A ready HTTP response (kept concrete so routing is a pure, unit-testable function).
pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: String,
    pub body: Vec<u8>,
    /// The chain-anchored content root of the site this asset came from (hex in the response header),
    /// or `None` for non-asset responses (directory index, errors).
    pub site_root: Option<Hash32>,
    /// `Some(name)` for a page of the MonerousD Veil site `name.mud`: served under the Veil's own, stricter policy
    /// ([`veil_csp`]) instead of the one the wallet's own apps get.
    pub veil: Option<String>,
}

/// A path under a site's VENDORED library directory — what an isolated realm (`<meta name="monerousd-realm"
/// content="isolated">`, framed with `sandbox="allow-scripts"`) imports from its opaque origin. The same markers the hole
/// scanner's `is_vendored_script` reads, so "realm asset" and "vendored script" are one set.
#[must_use]
pub fn is_realm_asset_path(target: &str) -> bool {
    let path = target.split(['?', '#']).next().unwrap_or("");
    (path.contains("/vendor/") || path.contains("/lib/monaco/") || path.contains("/node_modules/"))
        && (path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".css") || path.ends_with(".json") || path.ends_with(".ttf") || path.ends_with(".woff") || path.ends_with(".woff2") || path.ends_with(".wasm"))
}

/// The one CORS header this server ever writes: `Access-Control-Allow-Origin: null` on a realm asset answered to an opaque
/// origin (see the request admission). Inserted after the status line of an already-serialised response.
#[must_use]
pub fn with_realm_cors(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(i) = bytes.windows(2).position(|w| w == b"\r\n") {
        let hdr = b"Access-Control-Allow-Origin: null\r\nVary: Origin\r\n";
        bytes.splice(i + 2..i + 2, hdr.iter().copied());
    }
    bytes
}

impl HttpResponse {
    fn text(status: u16, reason: &'static str, body: &str) -> Self {
        HttpResponse {
            status,
            reason,
            content_type: "text/html; charset=utf-8".to_string(),
            body: body.as_bytes().to_vec(),
            site_root: None,
            veil: None,
        }
    }

    /// A node-computed JSON API response (chain-read endpoints served natively, no backend/VPS).
    fn json(status: u16, reason: &'static str, body: &str) -> Self {
        HttpResponse {
            status,
            reason,
            content_type: "application/json; charset=utf-8".to_string(),
            body: body.as_bytes().to_vec(),
            site_root: None,
            veil: None,
        }
    }

    /// Serialize to the wire. `head_only` omits the body (a HEAD request) but keeps Content-Length.
    /// DB-374: NO CORS header — the old `Access-Control-Allow-Origin: *` let any web page read every answer.
    pub fn to_bytes(&self, head_only: bool) -> Vec<u8> {
        // Strict, no-phone-home CSP (Pillar C.3): only same-origin; allow inline styles + wasm the
        // app needs, but NO external host, so a served page cannot beacon the user's activity out.
        // `frame-ancestors` names ONLY the MonerousD wallet's own origins (its Tauri webview + a loopback dev
        // preview) so the wallet can host the sovereign site inline in its Browser tab — this governs WHO may embed
        // the page, never where its data may flow (default-src stays locked to 'self').
        // `connect-src` names ONE address beside this host: the MonerousD wallet's own connect door on this same
        // computer (127.0.0.1:27751, `web3_bridge` in the wallet). A page served here in an ordinary browser reaches
        // its user's wallet through that door and nowhere else; it is loopback, so nothing leaves the machine, and
        // the door answers a page only after the wallet's user approved this site by name (user 2026-11-10: the
        // node-served copy "must work" when the official host is down). cons: none; no outside host is added.
        let app_csp = "default-src 'self'; connect-src 'self' http://127.0.0.1:27751; img-src 'self' data:; \
                   style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
                   font-src 'self' data:; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'self' tauri: http://tauri.localhost https://tauri.localhost http://localhost:* http://127.0.0.1:*";
        let veil_policy = self.veil.as_deref().map(veil_csp);
        let csp = veil_policy.as_deref().unwrap_or(app_csp);
        // Cache-Control: no-cache — a deployed sovereign app must SERVE ITS DEPLOYED BYTES on the next
        // load. Without any cache header, WKWebView heuristically caches ES modules, so the wallet's
        // Browser kept executing a superseded lib after a redeploy (MEASURED 2026-08-25: the Ion Swap
        // provider fix was live on :27752 while the webview ran the stale module and the Trade page
        // kept failing). no-cache means revalidate-every-load, not never-store.
        // cons: none — loopback refetch of KB-scale static files per page load; no term in chain
        // height, no state, and the node stays the backend (updates land instantly, Pillar C).
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
             Cache-Control: no-cache\r\n\
             Content-Security-Policy: {}\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
             X-MonerousD-Sovereign: node\r\n{}",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
            csp,
            if self.veil.is_some() { veil_headers() } else { String::new() },
        );
        if let Some(root) = self.site_root {
            head.push_str(&format!("X-MonerousD-Site-Root: {}\r\n", root.to_hex()));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// The live map of `dirKey → hosted site`. Populated from the node's local bundle store (which the
/// node keeps in sync with the on-chain `SitePublish` roots).
pub struct SovereignServer {
    /// ⛔ STALE-SITE CLASS (lane goods, 2026-11-12) — THE SITE HOST SERVES WHAT ITS FOLDER HOLDS NOW. MEASURED that day: the
    /// wallet's site host (PID 1298, started 24 days earlier) still served the IonSwap pages read at its start ("Ion Swap —
    /// private exchange for MoneroUSD", 5,281-byte index) while its folder held main's (3,338 bytes), and the wallet reuses
    /// whatever listens on its port, so every wallet launch showed the old app. Each request now compares the one file it
    /// serves with the folder (`refresh_from_disk`): a changed, added or removed file reloads that site, bundle and root
    /// together. SCALE: one `stat` per request and one reload of one site per change; constant in height, users and bonded
    /// nodes. PROTECTED BY: (b) ordinary code; every served byte is still checked against its bundle's root (`serve_asset`).
    sites: std::sync::RwLock<HashMap<String, HostedSite>>,
    /// The folder `load_all` read the sites from, so a changed site can be read again.
    fs_root: std::sync::Mutex<Option<std::path::PathBuf>>,
    /// A dApp BACKEND upstream on loopback (e.g. `127.0.0.1:7787`), if configured. Dynamic API paths
    /// (`/api/*`, `/v1/*`, `/events`, `/ws`) are reverse-proxied here SAME-ORIGIN, so a node-served
    /// dApp reaches its backend over loopback (Pillar C: the node is the backend) — NEVER a VPS, never
    /// cross-origin, never a phone-home. `None` = static-only (API paths 404). Loopback only (guarded).
    api_upstream: Option<String>,
    /// The live GHOSTDAG tip blue-score, shared from a running node's producer loop. When set, the
    /// server answers chain-READ endpoints (`/api/chain-tip`, `/v1/chain-tip`) NATIVELY from the real
    /// DAG tip — the node COMPUTES that part of the backend (Pillar C), so a dApp never needs a
    /// daemon/VPS/C++ wallet-rpc for the chain height. All OTHER `/api/*` still proxy to the backend.
    chain_tip: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// The node's live in-process confidential AMM (Pillar C: the node IS the IonSwap DEX backend, no
    /// VPS). Holds each pool's constant-product curve as node-internal state a swap MUTATES, and a
    /// bounded ring of TRADE EVENTS (direction + amount only — transparent market data, ZERO identity)
    /// the live chart renders. Shared behind a mutex so `&self` handlers can execute swaps / lock LP.
    /// The node's LIVE deployed-DSOL-contract accumulator — every IDE `/api/dc/deploy` appends the compiled
    /// contract here (an unbounded no-growth Poseidon MMR: state = its peaks + a 32-byte root, O(log N)). A
    /// deploy therefore causes a REAL observable state change: count increments and the root advances.
    deployed: Arc<std::sync::Mutex<crate::dsol::DsolRegistry>>,
}

/// Read one response body from THIS node's loopback tx-RPC (127.0.0.1:27780 by default — the process that
/// holds the full Node + peg ledger). Hand-rolled GET (no client dependency), the SAME loopback mirror the
/// chain-tip poller uses. Returns the body (headers stripped) or None if the node is unreachable — the caller
/// then fails closed (never a synthetic value).
/// The loopback port of THIS machine's tx-node — the node these `/api/*` routes mirror.
///
/// ⛔ IT MUST FOLLOW THE NODE, NOT A CONSTANT. This resolved to a hardcoded `27780` whenever
/// `MONEROUSD_LOOPBACK_RPC_PORT` was unset, but the wallet moves its node off the default port whenever the
/// configured one is squatted by a process that answers nothing. So the node ran happily on (measured) 60358
/// while every `/api/faucet/*`, `/api/letter/*` and `/api/reserves` call was still dialing 27780 — a dead port.
/// The faucet page then reported *"That address is invalid — paste your wallet's receive address"*, which sent
/// the user hunting a perfectly good address while the real fault was a proxy pointed at nothing.
///
/// `MONEROUSD_RPC_PORT` is the port this node was launched on and is set on every spawn path (desktop wallet,
/// launchd/systemd service, iOS in-process), so honoring it makes these routes track the node by construction.
fn loopback_tx_node_port() -> u16 {
    let parse = |k: &str| {
        std::env::var(k)
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|p| *p != 0)
    };
    // ⛔⛔⛔ AND IT MUST HONOUR THE NODE **URL** TOO — THE ONE THE LAUNCHER ACTUALLY SETS.
    //
    // MEASURED 2026-08-12 on the live rig: the serve-sites process (the wallet's own spawn, pid 27200)
    // carried
    //     MONEROUSD_NODE_URL=http://127.0.0.1:27841
    // and NEITHER port variable. The nodes were healthy on 27841/27842 (height 23476, peers 2,
    // mesh_joined true), yet this resolved to the 27780 default and every faucet call answered
    //     {"status":"UNAVAILABLE","error":"node not reachable for faucet status"}
    // so no wallet could be funded and no send could be attempted. The launcher stated exactly where the
    // node was, in the most explicit form available, and this function did not read it. The note above
    // already says "IT MUST FOLLOW THE NODE, NOT A CONSTANT"; reading only the two port variables followed
    // the node just far enough to miss the case the desktop wallet actually produces.
    //
    // Precedence: the loopback-specific port wins, then the node's own launch port, then the launcher's
    // full URL. Any of the three beats a hardcoded constant.
    //
    // cons: none. One env read and a character scan of a short string, once at first use — no request, no
    // new state, no storage, and no term that scales with height, notes or time.
    if let Some(p) = parse("MONEROUSD_LOOPBACK_RPC_PORT") {
        return p;
    }
    if let Some(p) = parse("MONEROUSD_RPC_PORT") {
        return p;
    }
    if let Ok(u) = std::env::var("MONEROUSD_NODE_URL") {
        // Everything after the LAST ':' is the port; digits only, so a trailing '/' or path is ignored.
        let mut tail = String::new();
        for c in u.trim().chars() {
            if c == ':' {
                tail.clear();
            } else {
                tail.push(c);
            }
        }
        let mut digits = String::new();
        for c in tail.chars() {
            if c >= '0' && c <= '9' {
                digits.push(c);
            }
        }
        if let Ok(p) = digits.parse::<u16>() {
            if p != 0 {
                return p;
            }
        }
    }
    27780
}

fn loopback_rpc_body(path: &str) -> Option<String> {
    use std::io::{Read, Write};
    let port: u16 = loopback_tx_node_port();
    // Same-MACHINE loopback to our OWN tx-node — never a real network hop, so it MUST answer sub-1s. The tx-node
    // keeps its RPC responsive under any gossip load by BOUNDING the relay pump's per-tick lock hold
    // (`node_runtime::drain_inbound` DRAIN_BUDGET_MS) — the DAG absorbs slow-arriving blocks, the serve side never
    // stalls. So this stays tight: a stall here means a real regression, not a busy node to wait out.
    let mut s = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(900),
    )
    .ok()?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .ok()?;
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

/// Loopback POST to the tx-node (:27780) with a JSON body — the sibling of `loopback_rpc_body` for write routes
/// (e.g. Letter seal/send/open, whose PQ crypto + relay ring live in the tx-node process). Same-machine only.
/// The ONE answer for a node-backed route whose loopback RPC did not answer: 503, legible, never a synthetic value
/// (PERFORMANCE: errors fail closed and name their real state). Every node-backed GET returns this instead of a default.
fn rpc_unavailable() -> HttpResponse {
    HttpResponse::json(
        503,
        "Service Unavailable",
        r#"{"status":"UNAVAILABLE","error":"the node's RPC did not answer; nothing is invented in its place"}"#,
    )
}

/// ⭐ THE ONE mint/burn quote answer (GET query and POST JSON alike). The asset must be a peg asset the bridge serves —
/// answered by its CANONICAL ticker from this list, so nothing the client sent is reflected (surface census 2026-10-04:
/// the GET form echoed any alphanumeric `asset` back, unbounded); the amount must be a decimal integer. Anything else is
/// refused 400, never quoted as zero. The ratio is the chain's public mint ratio / redeem floor — no state is read.
fn mint_burn_quote(dir: &str, asset: &str, amount: &str) -> HttpResponse {
    const ASSETS: [&str; 2] = ["BTC", "XMR"];
    let Some(ticker) = ASSETS.iter().find(|t| t.eq_ignore_ascii_case(asset.trim())) else {
        return HttpResponse::json(400, "Bad Request", r#"{"status":"REFUSED","error":"asset must be one the bridge serves: BTC or XMR"}"#);
    };
    let dir = match dir.trim() {
        "mint" | "" => "mint",
        "burn" => "burn",
        _ => return HttpResponse::json(400, "Bad Request", r#"{"status":"REFUSED","error":"op must be mint or burn"}"#),
    };
    let amount = amount.trim();
    let Some(amount) = (!amount.is_empty() && amount.len() <= 39 && amount.bytes().all(|b| b.is_ascii_digit()))
        .then(|| amount.parse::<u128>().ok())
        .flatten()
    else {
        return HttpResponse::json(400, "Bad Request", r#"{"status":"REFUSED","error":"amount must be a decimal integer"}"#);
    };
    let ratio = crate::peg::DEFAULT_MINT_RATIO_BPS as u128;
    let floor = crate::peg::DEFAULT_REDEEM_FLOOR_BPS as u128;
    let (quote, used_ratio) = if dir == "burn" {
        (amount.saturating_mul(floor) / 10_000, floor)
    } else {
        (amount.saturating_mul(10_000) / ratio.max(1), ratio)
    };
    HttpResponse::json(
        200,
        "OK",
        &format!(r#"{{"dir":"{dir}","asset":"{ticker}","amount":"{amount}","quote":"{quote}","ratio_bps":{used_ratio},"fee":"0"}}"#),
    )
}

/// One page or file of a `.mud` site: `rest` is `<name>/<path>` (an empty path is `index.html`). The node hands the
/// file over in pieces; a site whose bytes this node does not hold answers 503 with a page that reloads. Reading asks no
/// peer for anything.
// ── SAFE BROWSING ON THE VEIL (user 2026-11-12: "Add some securities to browsing so browsing doesnt open you up to losing
// your funds or getting your computer hacked. The goal is safe private browsing.") ────────────────────────────────────
//
// A `.mud` site is anyone's code. Every site and every one of the wallet's own apps is served from ONE address
// (127.0.0.1:27752), so without more a site's script could read another site's or an app's storage, call an app's
// back end, beacon out, or run a downloaded program. Each page of a site is therefore served under its own policy:
//   * `sandbox allow-scripts allow-forms`: the page runs in an opaque origin of its own, so it reaches no other site's
//     or app's storage or cookies; it opens no window, starts no download, and cannot navigate the wallet's window;
//   * every script, style, picture, font and form comes ONLY from that site's own path (`/mud/<name>/`), so one site
//     cannot load another site's or an app's code; `connect-src 'none'` and no outside host: a page cannot send what
//     it learns anywhere, not even to this machine's other ports (no beacon, no reach into the node or the wallet);
//   * no plugins, no frames inside it, no base-URL tricks; no camera, microphone, location, USB, Bluetooth, serial,
//     payment or clipboard reads (`Permissions-Policy`); no referrer; no MIME sniffing;
//   * a program file (an app, an installer, a script for a shell) is served as plain text, so a site can show it and
//     never hand the machine something to run.
// What protects it (AI RESISTANT, §2): (b) ordinary code, the browser engine's own sandbox and policy enforcement.
// The wallet adds its half: the page is framed with the same sandbox, and its wallet bridge answers a Veil site only
// with what that named site was allowed (dist/app.js, `_veilSiteCall`). cons: a site that relies on its own
// localStorage, cookies or fetch() of its own files does not get them (MEASURED nowhere yet; templates use none).

/// The Permissions-Policy every Veil page carries: no device and no payment sheet, whatever the page asks.
/// (No `Cross-Origin-Resource-Policy`: a sandboxed page has an origin of its own, and that header would refuse it its
/// own pictures, styles and scripts. No `X-Frame-Options`: `frame-ancestors` in the policy names who may frame it.)
pub const VEIL_PERMISSIONS: &str = "camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), hid=(), \
payment=(), clipboard-read=(), display-capture=(), publickey-credentials-get=()";

/// Extra response headers every Veil page this host serves carries.
fn veil_headers() -> String {
    format!("Permissions-Policy: {VEIL_PERMISSIONS}\r\n")
}

/// The policy a page of `name.mud` is served under by this node's site host: its own path only, nothing sent anywhere.
#[must_use]
pub fn veil_csp(name: &str) -> String {
    // the port the node's site host listens on, read as `main.rs` reads it
    let port = std::env::var("MONEROUSD_SOVEREIGN_PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(SOVEREIGN_DEFAULT_PORT);
    veil_csp_at(&[format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")], name)
}

/// The same policy for a page served from any of `bases` (the node's site host, or the wallet's own `veil:` scheme on
/// every platform): every script, style, picture and font from `<base>/mud/<name>/` only.
#[must_use]
pub fn veil_csp_at(bases: &[String], name: &str) -> String {
    let own = bases.iter().map(|b| format!("{b}/mud/{name}/")).collect::<Vec<_>>().join(" ");
    format!(
        "sandbox allow-scripts allow-forms; default-src 'none'; script-src {own} 'unsafe-inline'; style-src {own} 'unsafe-inline'; \
         img-src {own} data: blob:; media-src {own} blob:; font-src {own} data:; connect-src 'none'; frame-src 'none'; \
         worker-src 'none'; object-src 'none'; base-uri 'none'; form-action {own}; \
         frame-ancestors tauri: http://tauri.localhost https://tauri.localhost http://localhost:* http://127.0.0.1:*"
    )
}

/// A file a computer might RUN when it is handed one: served as text so a site can show it and never deliver it.
#[must_use]
pub fn veil_runnable(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe" | "msi" | "bat" | "cmd" | "com" | "scr" | "ps1" | "vbs" | "jar" | "apk" | "dmg" | "pkg" | "app" | "command" | "sh" | "bash" | "zsh"
            | "scpt" | "applescript" | "workflow" | "deb" | "rpm" | "appimage" | "run" | "bin" | "dll" | "so" | "dylib" | "lnk" | "reg" | "hta"
            | "msix" | "appx" | "iso" | "img" | "torrent" | "desktop" | "xpi" | "crx"
    )
}

/// The small script every Veil HTML page gets from the node, so the wallet's Back works from inside a site and
/// Backspace steps back: it tells the wallet frame which page is showing, and asks it to step back. It also gives the
/// page `window.monerousd` — `request(method, params)` and `backend.read(keys)` / `backend.call(entrypoint, argv)` /
/// `backend.seal(text)` / `backend.open(sealed)` — each one message to the frame that holds the page, answered by the
/// wallet only as this named site (`dist/app.js` `_veilSiteCall`). It reads and sends nothing else.
pub const VEIL_NAV_JS: &str = "<script>(function(){try{if(window.parent===window)return;var p=window.parent;\
p.postMessage({type:'monerousd:veil-page',href:String(location.href)},'*');\
var n=0,w={};window.addEventListener('message',function(e){var d=e.data;if(e.source!==p||!d||d.type!=='monerousd:res'||!w[d.id])return;\
var q=w[d.id];delete w[d.id];if(d.ok)q[0](d.result);else q[1](new Error(d.error));});\
var r=function(m,a){return new Promise(function(y,x){var i='v'+(++n);w[i]=[y,x];p.postMessage({type:'monerousd:rpc',id:i,method:m,params:a||{}},'*');});};\
window.monerousd={request:r,backend:{read:function(k){return r('backendRead',{keys:k}).then(function(v){return v.values;});},\
call:function(e,a){return r('backendCall',{entrypoint:e,argv:a});},seal:function(t){return r('seal',{text:t});},\
open:function(s){return r('open',{sealed:s});}}};\
document.addEventListener('keydown',function(e){if(e.key!=='Backspace'||e.defaultPrevented||e.metaKey||e.ctrlKey||e.altKey)return;\
var t=e.target;if(t&&(t.isContentEditable||/^(input|textarea|select)$/i.test(t.tagName)))return;\
e.preventDefault();p.postMessage({type:'monerousd:veil-back'},'*');},true);}catch(_){}})();</script>";

fn veil_response(name: &str, file: &str, body: Vec<u8>) -> HttpResponse {
    let (content_type, body) = veil_body(file, body);
    HttpResponse { status: 200, reason: "OK", content_type, body, site_root: None, veil: Some(name.to_string()) }
}

/// What a Veil file is served as, by any host: a program as plain text, an HTML page with the Back script; anything
/// else as itself. ONE rule for the node's site host and the wallet's `veil:` scheme.
#[must_use]
pub fn veil_body(file: &str, body: Vec<u8>) -> (String, Vec<u8>) {
    let content_type = if veil_runnable(file) { "text/plain; charset=utf-8".to_string() } else { content_type_for(file) };
    let body = if content_type.starts_with("text/html") { with_nav(body) } else { body };
    (content_type, body)
}

/// `html` with [`VEIL_NAV_JS`] first inside its `<head>` (or at its very start when it has none).
pub fn with_nav(html: Vec<u8>) -> Vec<u8> {
    let at = {
        let head = html.windows(5).position(|w| w.eq_ignore_ascii_case(b"<head"));
        head.and_then(|i| html[i..].iter().position(|b| *b == b'>').map(|j| i + j + 1)).unwrap_or(0)
    };
    let mut out = Vec::with_capacity(html.len() + VEIL_NAV_JS.len());
    out.extend_from_slice(&html[..at]);
    out.extend_from_slice(VEIL_NAV_JS.as_bytes());
    out.extend_from_slice(&html[at..]);
    out
}

fn mud_page(rest: &str) -> HttpResponse {
    let (name, file) = rest.split_once('/').unwrap_or((rest, ""));
    // a folder's page is its index.html
    let file = pct_decode(file);
    let file = if file.is_empty() || file.ends_with('/') { format!("{file}index.html") } else { file };
    if crate::veil::mud_name(&format!("{name}{}", crate::veil::MUD_SUFFIX)).as_deref() != Some(name) || !crate::veil::site_path_ok(&file) {
        return HttpResponse::text(404, "Not Found", "<h1>404</h1><p>That is not a site address.</p>");
    }
    let mut body: Vec<u8> = Vec::new();
    loop {
        let ask = format!(r#"{{"host":"{name}.mud","path":"{}","from":{}}}"#, json_escape_ascii(&file), body.len());
        let Some(reply) = loopback_rpc_post("/veil/file", &ask) else {
            return HttpResponse::text(503, "Service Unavailable", "<h1>503</h1><p>This wallet's node did not answer.</p>");
        };
        match json_str_field_local(&reply, "status").as_deref() {
            Some("OK") => {
                let piece = json_str_field_local(&reply, "hex").and_then(|h| crate::rpc_http::hex_decode(&h)).unwrap_or_default();
                let size = crate::rpc_http::json_num_field(&reply, "size").unwrap_or(0) as usize;
                let got = piece.len();
                body.extend_from_slice(&piece);
                if body.len() >= size || got == 0 {
                    return veil_response(name, &file, body);
                }
            }
            Some("NOT_HELD") => {
                return HttpResponse::text(
                    503,
                    "Service Unavailable",
                    "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1\"><title>Fetching privately</title>\
<style>body{margin:0;height:100vh;display:grid;place-items:center;background:#0b0b0d;color:#c7c7cf;font:15px -apple-system,system-ui,sans-serif}\
i{display:block;width:34px;height:34px;margin:0 auto 14px;border-radius:50%;border:3px solid #26262e;border-top-color:#ff6a00;animation:s .8s linear infinite}\
@keyframes s{to{transform:rotate(360deg)}}</style><div><i></i>Fetching this site privately from the Veil…</div>",
                );
            }
            _ => return HttpResponse::text(404, "Not Found", "<h1>404</h1><p>No such page on this site.</p>"),
        }
    }
}

fn loopback_rpc_post(path: &str, body: &str) -> Option<String> {
    use std::io::{Read, Write};
    let port: u16 = loopback_tx_node_port();
    // Same-machine loopback to our own tx-node (see loopback_rpc_body) — sub-1s by construction (bounded pump lock).
    let mut s = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(900),
    )
    .ok()?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(2000)));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

impl SovereignServer {
    pub fn new() -> Self {
        SovereignServer {
            sites: std::sync::RwLock::new(HashMap::new()),
            fs_root: std::sync::Mutex::new(None),
            api_upstream: None,
            chain_tip: None,
            deployed: Arc::new(std::sync::Mutex::new(crate::dsol::DsolRegistry::new())),
        }
    }

    /// Share the live DAG-tip blue-score so the server can answer chain-read endpoints natively.
    pub fn set_chain_tip(&mut self, tip: Arc<std::sync::atomic::AtomicU64>) {
        self.chain_tip = Some(tip);
    }

    /// Set the loopback dApp-backend upstream that `/api/*`,`/v1/*`,`/events`,`/ws` reverse-proxy to.
    /// REJECTS a non-loopback host (a backend upstream is ALWAYS same-machine — no VPS, no routable IP,
    /// Pillar C.3): a routable upstream would make the sovereign path leak to an operator.
    pub fn set_api_upstream(&mut self, upstream: Option<String>) {
        self.api_upstream = upstream.filter(|u| is_loopback_authority(u));
    }

    pub fn api_upstream(&self) -> Option<&str> {
        self.api_upstream.as_deref()
    }

    /// The dirKeys currently served, sorted (for the directory index + logging).
    pub fn dirs(&self) -> Vec<String> {
        let mut d: Vec<String> = self.read_sites().keys().cloned().collect();
        d.sort();
        d
    }

    /// The chain-anchored root of a hosted site (what its `SitePublish` anchors), if hosted.
    pub fn root_of(&self, dir: &str) -> Option<Hash32> {
        self.read_sites().get(dir).map(|s| s.root)
    }

    fn read_sites(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, HostedSite>> {
        self.sites.read().unwrap_or_else(|e| e.into_inner())
    }

    fn install(&self, dir: &str, bundle: SiteBundle, stamps: Option<HashMap<String, FileStamp>>) -> Hash32 {
        let root = bundle.root();
        self.sites
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(dir.to_string(), HostedSite { dir: dir.to_string(), bundle, root, stamps });
        root
    }

    /// Host a site's assets under `dir`. Builds the merkle-committed bundle + records its content root.
    pub fn host_site(&mut self, dir: &str, assets: Vec<Asset>) -> Result<Hash32, SiteError> {
        let bundle = site::build_bundle(assets)?;
        Ok(self.install(dir, bundle, None))
    }

    /// Load one site directory from disk (`fs_root/dir/**`) into a hosted bundle. Every file becomes
    /// an [`Asset`] keyed by its path relative to the site root (`/index.html`, `/lib/swap-client.js`).
    /// The files' stamps are read BEFORE their bytes, so a file written between the two reads differs from its stamp on
    /// the next request and is read again — never held stale behind a stamp that already names the new write.
    pub fn load_dir(&self, dir: &str, fs_root: &Path) -> std::io::Result<Hash32> {
        let site_root = fs_root.join(dir);
        let mut stamps = HashMap::new();
        collect_stamps(&site_root, &site_root, &mut stamps)?;
        let mut assets = Vec::new();
        collect_assets(&site_root, &site_root, &mut assets)?;
        let bundle = site::build_bundle(assets).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(self.install(dir, bundle, Some(stamps)))
    }

    /// Read a site again when the one file a request asks for differs from what the host loaded: changed, added or
    /// removed (`HostedSite::stamps`), or a site folder added since the host started. A site hosted from anywhere but the
    /// folder is never touched. A path with a `..` segment is answered from what is held, never looked up on disk.
    fn refresh_from_disk(&self, dir: &str, asset_path: &str) {
        let Some(fs_root) = self.fs_root.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return;
        };
        if dir.is_empty() || dir.starts_with('.') || dir.starts_with('_') || dir.contains("..") || asset_path.split('/').any(|s| s == "..") {
            return;
        }
        let site_dir = fs_root.join(dir);
        let on_disk = std::fs::metadata(site_dir.join(asset_path.trim_start_matches('/')))
            .ok()
            .filter(|m| m.is_file())
            .map(|m| file_stamp(&m));
        let changed = match self.read_sites().get(dir) {
            None => site_dir.is_dir(),
            Some(h) => h.stamps.as_ref().is_some_and(|st| st.get(asset_path).copied() != on_disk),
        };
        if changed {
            match self.load_dir(dir, &fs_root) {
                Ok(root) => eprintln!("[sites] {dir}: {asset_path} changed on disk; the site is read again (root {}…)", &root.to_hex()[..16]),
                Err(e) => eprintln!("[sites] {dir}: {asset_path} changed on disk but the site could not be read again ({e}); the held copy stays"),
            }
        }
    }

    /// Load EVERY site subdirectory under `fs_root` (each immediate child dir = one dirKey). Skips
    /// top-level files (README, registry manifests) and hidden dirs. Returns `(dir, root)` per site.
    pub fn load_all(&mut self, fs_root: &Path) -> std::io::Result<Vec<(String, Hash32)>> {
        // O1-INFINITY-REVIEWED: the site folder holds dApps' static web files, never chain state; remembering where they were read from rebuilds no authority from storage
        *self.fs_root.lock().unwrap_or_else(|e| e.into_inner()) = Some(fs_root.to_path_buf());
        let mut out = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(fs_root)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name.starts_with('_') {
                continue; // hidden / non-site metadata (_registry.json etc.)
            }
            if e.path().is_dir() {
                let root = self.load_dir(&name, fs_root)?;
                out.push((name, root));
            }
        }
        Ok(out)
    }

    /// Pure request router (unit-testable without a socket). Maps a method + target to a response.
    /// `GET /<dir>/` → the site's `/index.html`; `GET /<dir>/<path>` → `/<path>`; `GET /` → directory.
    pub fn respond(&self, method: &str, target: &str) -> HttpResponse {
        if method != "GET" && method != "HEAD" {
            return HttpResponse::text(405, "Method Not Allowed", "<h1>405</h1>");
        }
        // Drop any query string / fragment; keep just the path.
        let path = target.split(['?', '#']).next().unwrap_or("/");

        // MonerousD Veil: `/mud/<name>/<path>` is the site `<name>.mud`, read from THIS node's site store through its
        // own RPC, every byte already checked against the root the chain anchors for that name.
        if let Some(rest) = path.strip_prefix("/mud/") {
            return mud_page(rest);
        }

        // Root + directory catalog → a listing of the node-hosted dApps.
        if path == "/" || path == "/_directory" || path == "/_directory/" {
            return self.directory_index();
        }

        // Split "/<dir>/<rest...>" — the first non-empty segment is the site dirKey.
        let trimmed = path.trim_start_matches('/');
        let (dir, rest) = match trimmed.split_once('/') {
            Some((d, r)) => (d, r),
            None => {
                // "/<dir>" with no trailing slash — the site's index (equivalent to "/<dir>/").
                (trimmed, "")
            }
        };
        // The asset path within the bundle: an empty/`""`/`"/"` rest = the index.
        let asset_path = if rest.is_empty() || rest == "/" {
            "/index.html".to_string()
        } else {
            format!("/{}", rest.trim_start_matches('/'))
        };
        // the folder may have changed under the host since it read this site (a deploy, a checkout)
        self.refresh_from_disk(dir, &asset_path);
        let sites = self.read_sites();
        let site = match sites.get(dir) {
            Some(s) => s,
            None => {
                return HttpResponse::text(404, "Not Found", "<h1>404</h1><p>No such site.</p>")
            }
        };

        match self.serve_asset(site, &asset_path) {
            Some(resp) => resp,
            None => {
                // SPA deep-link fallback: a path with no file extension resolves to index.html so the
                // app's own client-side router handles it (a real missing FILE still 404s).
                if !last_segment_has_ext(&asset_path) {
                    if let Some(resp) = self.serve_asset(site, "/index.html") {
                        return resp;
                    }
                }
                HttpResponse::text(404, "Not Found", "<h1>404</h1><p>No such asset.</p>")
            }
        }
    }

    /// Serve one asset from a bundle WITH the merkle self-check: build the served asset (bytes +
    /// inclusion proof), authenticate it against the chain-anchored root, and only then return it. A
    /// corrupt local store fails closed (500) rather than serving unauthenticated bytes.
    fn serve_asset(&self, site: &HostedSite, asset_path: &str) -> Option<HttpResponse> {
        let served: ServedAsset = site.bundle.serve(asset_path)?;
        if !site::verify_served(&site.root, asset_path, &served) {
            // Self-verify failed — the held bytes do not authenticate against the anchored root.
            return Some(HttpResponse::text(
                500,
                "Internal Server Error",
                "<h1>500</h1><p>asset failed root verification</p>",
            ));
        }
        Some(HttpResponse {
            status: 200,
            reason: "OK",
            content_type: content_type_for(asset_path),
            body: served.bytes,
            site_root: Some(site.root),
            veil: None,
        })
    }

    fn directory_index(&self) -> HttpResponse {
        let mut body = String::from(
            "<!doctype html><meta charset=utf-8><title>MonerousD — sovereign node</title>\
             <h1>MonerousD sovereign node</h1><p>Node-served, chain-anchored dApps (loopback, private):</p><ul>",
        );
        for dir in self.dirs() {
            let root = self.root_of(&dir).map(|r| r.to_hex()).unwrap_or_default();
            body.push_str(&format!(
                "<li><a href=\"/{d}/\">{d}</a> <code>root {r}…</code></li>",
                d = dir,
                r = &root[..root.len().min(16)],
            ));
        }
        body.push_str("</ul>");
        HttpResponse::text(200, "OK", &body)
    }

    /// Bind the loopback sovereign server on `port` and serve forever (thread per connection). Binds
    /// `127.0.0.1` ONLY — never a routable interface (a same-machine private surface, Pillar C.3).
    /// Node-COMPUTED API endpoints the sovereign server answers itself (Pillar C) instead of proxying:
    /// the chain height is read from the live GHOSTDAG tip's real blue-score, so a dApp needs no daemon
    /// / VPS / C++ wallet-rpc for it. Returns `None` for anything not natively handled (→ backend proxy).
    fn native_api(&self, method: &str, target: &str) -> Option<HttpResponse> {
        if method != "GET" && method != "HEAD" {
            return None;
        }
        let path = target.split(['?', '#']).next().unwrap_or("");
        match path {
            // The Ion Swap Trade panel gates its render on chain-tip; answer it from the real DAG tip
            // (blue-score). 1s target spacing → blockTimeSec:1. Same shape for the frontend + v1 aliases.
            "/api/chain-tip" | "/v1/chain-tip" => {
                // No live node wired → return None so the request proxies to the backend; never emit a
                // synthetic height. When wired, `h` is the genuine blue-score of the current DAG tip.
                let tip = self.chain_tip.as_ref()?;
                let h = tip.load(std::sync::atomic::Ordering::Relaxed);
                let body = format!(r#"{{"height":{h},"blockTimeSec":1,"protocolVersion":"v1"}}"#);
                Some(HttpResponse::json(200, "OK", &body))
            }
            // NODE-FIRST CONFIDENTIAL SOLVENCY (MoneroUSD.org reserves page). Read the live peg-ledger
            // attestation from THIS node's tx-RPC (:27780 — the process that holds the peg ledger), the same
            // loopback mirror chain-tip uses. The payload is value-hiding commitments + the proven backing
            // ratio — NO amount / supply / count leaves the node (digital-cash pillar). Fail-closed 503 when
            // the node is unreachable — never a synthetic figure.
            "/api/reserves" | "/v1/reserves" => match loopback_rpc_body("/get_solvency") {
                Some(b) if b.trim_start().starts_with('{') => {
                    Some(HttpResponse::json(200, "OK", b.trim()))
                }
                _ => Some(HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node not reachable for confidential-solvency read"}"#,
                )),
            },
            // LETTER (private P2P messaging) — the read side. `identity` = this node's own ML-KEM Letter address;
            // `inbox` = the metadata-blind relay's CONSTANT cover window (crate::letter). Both loopback-mirror the
            // tx-node (:27780) where the PQ crypto + relay ring live. Zero recipient/volume metadata on the wire.
            "/api/letter/identity" | "/v1/letter/identity" => {
                match loopback_rpc_body("/letter/identity") {
                    Some(b) if b.trim_start().starts_with('{') => {
                        Some(HttpResponse::json(200, "OK", b.trim()))
                    }
                    _ => Some(HttpResponse::json(
                        503,
                        "Service Unavailable",
                        r#"{"status":"UNAVAILABLE","error":"node not reachable for letter identity"}"#,
                    )),
                }
            }
            "/api/letter/inbox" | "/v1/letter/inbox" => match loopback_rpc_body("/letter/inbox") {
                Some(b) if b.trim_start().starts_with('{') => {
                    Some(HttpResponse::json(200, "OK", b.trim()))
                }
                _ => Some(HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node not reachable for letter inbox"}"#,
                )),
            },
            "/api/letter/scan" | "/v1/letter/scan" => match loopback_rpc_body("/letter/scan") {
                Some(b) if b.trim_start().starts_with('{') => {
                    Some(HttpResponse::json(200, "OK", b.trim()))
                }
                _ => Some(HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node not reachable for letter scan"}"#,
                )),
            },
            // TESTNET note-forwarder (dev tool) — read side. `identity` = the tool's receive address + network;
            // `status` = held / forwarded / available / demo_balance. Loopback-mirror the tx-node (:27780) where the
            // conservation-only forwarder + its network gate live. Zero value/allocation ever expressed here.
            "/api/faucet/identity" | "/v1/faucet/identity" => {
                match loopback_rpc_body("/faucet/identity") {
                    Some(b) if b.trim_start().starts_with('{') => {
                        Some(HttpResponse::json(200, "OK", b.trim()))
                    }
                    _ => Some(HttpResponse::json(
                        503,
                        "Service Unavailable",
                        r#"{"status":"UNAVAILABLE","error":"node not reachable for faucet identity"}"#,
                    )),
                }
            }
            "/api/faucet/status" | "/v1/faucet/status" => {
                match loopback_rpc_body("/faucet/status") {
                    Some(b) if b.trim_start().starts_with('{') => {
                        Some(HttpResponse::json(200, "OK", b.trim()))
                    }
                    _ => Some(HttpResponse::json(
                        503,
                        "Service Unavailable",
                        r#"{"status":"UNAVAILABLE","error":"node not reachable for faucet status"}"#,
                    )),
                }
            }
            // NODE-COMPUTED mint/burn quote (IonSwap PSM) — a pure function of the consensus over-collateralization
            // ratio the node ENFORCES on every peg-in / wrapped mint (crate::peg::DEFAULT_MINT_RATIO_BPS = 150%) and
            // the redeem floor (DEFAULT_REDEEM_FLOOR_BPS = 100%). The node IS the backend (Pillar C) — no VPS, no
            // oracle. Read via `?amount=<atomic>&dir=mint|burn&asset=<sym>`. mint: deposit `amount` collateral →
            // mint amount·10000/ratio USDm (150% ⇒ amount/1.5). burn: burn `amount` USDm → release amount·floor/10000
            // collateral (100% ⇒ amount) at the solvency floor.
            "/api/mint-burn/quote" => {
                let q = target.split('?').nth(1).unwrap_or("");
                let (mut amount, mut dir, mut asset) = ("", "mint", "");
                for kv in q.split('&') {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    match k {
                        "amount" => amount = v,
                        "dir" | "op" => dir = v,
                        "asset" => asset = v,
                        _ => {}
                    }
                }
                Some(mint_burn_quote(dir, asset, amount))
            }
            // DSOL v2 per-layer PQ + privacy PROOF (the language custom tokens + wrapped coins are written
            // in). The node COMPUTES this by exercising each DSOL primitive live (a real Poseidon commit, a
            // real WHIR prove+verify, a real ML-KEM encap/decap, a real ML-DSA sign/verify) — so a viewer
            // gets earned evidence per layer, never a claim. `all_pq:true` only if every layer actually held.
            // Synthetic self-test inputs (no real chain state), so serving it reveals ZERO value/identity.
            "/api/dsol/manifest" => {
                Some(HttpResponse::json(200, "OK", &crate::dsol::manifest_json()))
            }
            // ⭐⭐⭐ THE PRICE, QUOTED BY THE NODE THAT WILL CHARGE IT. The client asks rather than
            // computes, so the number a user is shown and the number the gate enforces are the SAME
            // number by construction.
            //
            // ⛔ WHAT THIS REPLACES: `pages/token-create.js` computed its own "Creation Bond" from a
            // local tier curve mirroring `backend/tokens/create.js` — a file that no longer exists. It
            // displayed 10,000 / 2,500 / 500 USDm while the live route charged NOTHING. Mirrored
            // constants drift the moment one side moves; a quote cannot.
            p if p.starts_with("/api/tokens/create_fee") => {
                let raw = target
                    .split('?')
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "symbol"))
                    .map(|(_, v)| pct_decode(v))
                    .unwrap_or_default();
                // ⛔ THE SAME CANONICALIZATION THE GATE USES. If the quote priced the raw string and the
                // gate priced the filtered one, "MO-ON" would be quoted as a 5-char symbol and charged as
                // a 4-char one — the drift this route exists to make impossible.
                let symbol = canonical_symbol(&raw);
                // The kind prices a creation (`params::asset_create_fee_atomic`, 2026-11-10): `kind=nft` asks for an NFT's
                // price, anything else for a token's. The gate reads the same function from the creation's own kind.
                let nft = target.split('?').nth(1).unwrap_or("").split('&').any(|kv| kv == "kind=nft");
                // §12.6: `art_bytes=N` asks for the price of a creation that puts a picture of N bytes on the chain. The
                // answer also states the price of one picture kilobyte and the largest picture the chain keeps for this
                // kind, so a page that prices many pictures asks once. The gate reads the same function.
                let art_bytes = target
                    .split('?')
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == "art_bytes"))
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let atomic = crate::asset_tx::creation_price_of(nft, art_bytes);
                Some(HttpResponse::json(
                    200,
                    "OK",
                    &format!(
                        "{{\"symbol\":\"{}\",\"fee_atomic\":{},\"fee_usdm\":\"{}\",\"asset\":\"USDm\",\"tier\":\"{}\",\"art_bytes\":{},\"picture_kb_fee_atomic\":{},\"art_max_bytes\":{}}}",
                        symbol,
                        atomic,
                        format_atomic_usdm(atomic),
                        create_fee_kind_name(nft),
                        art_bytes,
                        crate::dir_entry_tx::DIR_KB_FEE_ATOMIC,
                        if nft { crate::directory::NFT_ART_MAX } else { crate::directory::TOKEN_ART_MAX },
                    ),
                ))
            }
            // The node's deployed-DSOL token/wrapped/nft TYPE registry (the Explorer / IonSwap / IDE lists).
            // TYPE metadata only — symbol/name/kind/content-addressed id; never a holder's balance. Node-
            // computed: each id is blake3 of the DSOL v2 bytecode the node compiles for that asset.
            "/api/tokens" | "/v1/tokens" | "/api/tokens/verified" => {
                // The discovery list is REGENERATED at serve from the deterministic wrapped descriptors
                // (f(network)) — the node stores no per-token map, so this is O(1) node state (user-created
                // tokens arrive the same way, from the replicated DA deploy stream).
                let descs = crate::dsol::listed_descriptors();
                let verified_only = path == "/api/tokens/verified";
                Some(HttpResponse::json(
                    200,
                    "OK",
                    &crate::dsol::tokens_json(&descs, verified_only),
                ))
            }
            // App BOOT CONFIG the IonSwap/Explorer bundles read at startup (they consume `.apiBase`). apiBase=""
            // means SAME-ORIGIN: the app calls /api/* on the very node that served it (Pillar C — node is the
            // backend, no VPS). blockTimeSec/protocolVersion mirror the live chain-tip contract.
            // ⭐⭐⭐ THE BOOT CONFIG CARRIES THE LIVE FEE RATE, so no page has to know it.
            //
            // ⛔ WHAT THIS REPLACES: `token-create.js` told users "traders pay only the 0.30% protocol
            // fee" and showed a "Pool fee 0.30%" row — for a pool that was DELETED, at a rate the chain
            // never charged. Every hardcoded rate in a page is a claim about money that nothing enforces.
            // `orderFillFeeBps` here is the SAME value `execute_order_fill` verifies against.
            "/api/config" | "/v1/config" => {
                let p = crate::params::ChainParams::default();
                // The withdraw band travels too. The peg-out fee is `min + (max-min)·u²` in the
                // reserve utilization `u`, and the reserve is CONFIDENTIAL — so a client can never
                // compute the exact rate and must state the BAND instead. Shipping only a flat number
                // is how `trade.js` came to promise "0.10% unwrap fee" against a real band topping out
                // at 90%: an understatement a user could act on and lose most of a redemption to.
                let body = format!(
                    r#"{{"apiBase":"","network":"testnet","blockTimeSec":1,"protocolVersion":"v1","sovereign":true,"orderFillFeeBps":{},"orderFillFeePct":"{}","feeModel":"burn","withdrawFeeMinBps":{},"withdrawFeeMaxBps":{},"withdrawFeeMinPct":"{}","withdrawFeeMaxPct":"{}","withdrawFeeShape":"min + (max-min)*u^2 in reserve utilization"}}"#,
                    p.order_fill_fee_bps,
                    format_bps_pct(p.order_fill_fee_bps),
                    p.withdraw_fee_min_bps,
                    p.withdraw_fee_max_bps,
                    format_bps_pct(u64::from(p.withdraw_fee_min_bps)),
                    format_bps_pct(u64::from(p.withdraw_fee_max_bps)),
                );
                let body = body.as_str();
                Some(HttpResponse::json(200, "OK", body))
            }
            // Verified-asset discovery (alias of /api/tokens/verified): the same real verified DSOL token list,
            // regenerated at serve from the deterministic wrapped descriptors — O(1) node state.
            "/v1/verified-assets" | "/api/verified-assets" => {
                let descs = crate::dsol::listed_descriptors();
                Some(HttpResponse::json(
                    200,
                    "OK",
                    &crate::dsol::tokens_json(&descs, true),
                ))
            }
            // ⛔ RETIRED SURFACE (user ruling 2026-08-26). These answered from a SEEDED curve —
            // blake3-derived fake reserves presented as market data, the simulator class the fund-safety
            // audit deleted. No invented number may be served: the honest answer until the P2P
            // limit-order book exists is a refusal that says why.
            "/api/prices" | "/v1/prices" => Some(HttpResponse::json(
                503,
                "RETIRED",
                "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}",
            )),
            // ⭐ THE CHAIN'S OWN COIN PRICES, FOR A PAGE (2026-11-10: IonSwap showed no real Bitcoin or Monero price unless a
            // wallet handed it one). These are the chain's PRICE MARKS and nothing else: each bonded validator samples the
            // onion price relays by itself, and the bond-weighted median two thirds of bond signed is carried in a block
            // (`price_mark_tx`); `/price_marks` on this node's own tx-RPC already serves them, with dollars per coin formed
            // by the one coin table (`bridge_assets`). This arm mirrors that answer for the pages this host serves. No
            // number is formed here: a chain with no mark answers an empty list, and an unreachable node answers 503.
            // DIGITAL CASH: public market prices only; the request names no coin, no user and no amount.
            "/api/price-marks" | "/v1/price-marks" => {
                let marks = loopback_rpc_body("/price_marks").and_then(|b| serde_json::from_str::<serde_json::Value>(b.trim()).ok());
                match marks.as_ref().and_then(|v| v.get("marks")).and_then(|m| m.as_array()) {
                    Some(list) => {
                        let mut items = Vec::new();
                        for m in list {
                            let text = |k: &str| m.get(k).and_then(|x| x.as_str()).unwrap_or("");
                            let (asset, name, usd) = (text("asset"), text("name"), text("usd"));
                            // only a decimal the node itself formed is passed on as a JSON number
                            let numeric = !usd.is_empty() && usd.bytes().all(|c| c.is_ascii_digit() || c == b'.') && usd.bytes().filter(|c| *c == b'.').count() <= 1;
                            if asset.is_empty() || !asset.bytes().all(|c| c.is_ascii_alphanumeric()) || !numeric {
                                continue;
                            }
                            let epoch = m.get("epoch").and_then(serde_json::Value::as_u64).unwrap_or(0);
                            let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == ' ').collect();
                            items.push(format!("{{\"asset\":\"{asset}\",\"name\":\"{name}\",\"usd\":{usd},\"epoch\":{epoch}}}"));
                        }
                        Some(HttpResponse::json(200, "OK", &format!("{{\"status\":\"OK\",\"source\":\"chain price marks\",\"prices\":[{}]}}", items.join(","))))
                    }
                    None => Some(HttpResponse::json(
                        503,
                        "Service Unavailable",
                        r#"{"status":"UNAVAILABLE","error":"node not reachable for the chain's price marks"}"#,
                    )),
                }
            }
            // The DSOL token registry's accumulator ROOT — the node's ENTIRE persistent registry state is
            // this 32-byte unbounded-Poseidon-MMR root + a count + its peaks (= popcount(count), ~log2 of
            // the count). There is NO ceiling on token creation (2^128 index space, like Solidity), yet the
            // peak set stays a tiny handful at any count. Proves the no-growth axis is live.
            "/api/dsol/registry-root" => {
                let mut reg = crate::dsol::DsolRegistry::new();
                for c in crate::dsol::listed_descriptors() {
                    reg.register(&c);
                }
                let root = reg.root_bytes();
                let hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
                let body = format!(
                    r#"{{"root":"{hex}","count":{},"peaks":{},"model":"unbounded-poseidon-mmr","token_ceiling":"none","state":"log-of-count"}}"#,
                    reg.count(),
                    reg.peak_count()
                );
                Some(HttpResponse::json(200, "OK", &body))
            }
            // ALL asset classes (fungible token, NFT collection, wrapped coin, AMM pool, escrow, generic)
            // ride the SAME unbounded no-growth accumulator: unlimited creation, O(log N) node state, PQ,
            // private ownership. The node PROVES it by registering one of each class and reporting the live
            // peaks + root. This is the axis that beats Ethereum outright — NFTs included (no per-token bloat).
            "/api/dsol/asset-classes" => Some(HttpResponse::json(
                200,
                "OK",
                &crate::dsol::asset_classes_json(),
            )),
            // PRIVATE-CHAIN block explorer surface. A private chain CANNOT and MUST NOT show tx / amount /
            // owner / linkage (digital-cash pillar) — so the explorer is an ASSET-TYPE + logo DISCOVERY view:
            // the token / NFT / wrapped types with their content-addressed logo + verified badge, and NOTHING
            // else. It carries ZERO value/owner/tx metadata by construction (that is the point — a private
            // chain's explorer tracks assets, not transactions). Logos are content-addressed so they are
            // always correct; the image bytes are served as chain-anchored static assets, never node state.
            // ⭐ Live-DAG feed for the explorer scene — same-origin proxy of the node's /dag_recent
            // (real ids, parent edges, blue scores, selected-chain flags: consensus-public structure
            // gossip already hands every peer; no amounts, no real counts). The scene formerly pointed
            // at a retired clearnet host the CSP rightly blocked — the node IS the backend (Pillar C).
            "/api/explorer/dag-recent" | "/v1/explorer/dag-recent" => {
                match loopback_rpc_body("/dag_recent") {
                    Some(b) => Some(HttpResponse::json(200, "OK", &b)),
                    // no node ⇒ 503 like every node-backed read: an empty list at 200 reads as "no blocks" (surface census)
                    None => Some(rpc_unavailable()),
                }
            }
            // ⭐ SATOSHI §10 (user ruling 2026-10-05: the takeover cost is SHOWN) — the node's public custody figures for the
            // explorer: total custody weight, the bottom-2/3 effective security, and the SAT a newcomer must bond to hold more
            // than 2/3 of custody. Public consensus state only; the confidential reserve is never read.
            "/api/explorer/takeover-cost" | "/v1/explorer/takeover-cost" => match loopback_rpc_body("/takeover_cost") {
                Some(b) => Some(HttpResponse::json(200, "OK", &b)),
                None => Some(rpc_unavailable()),
            },
            "/api/explorer/assets" | "/v1/explorer/assets" => {
                let descs = crate::dsol::listed_descriptors();
                Some(HttpResponse::json(
                    200,
                    "OK",
                    &crate::dsol::tokens_json(&descs, false),
                ))
            }
            // Explorer search: matches ASSET TYPES by symbol/name (discovery metadata only) — a private
            // chain has no txs / holders to search, so this returns asset types + their content-addressed
            // logo, never a tx / owner / amount. Node-computed from the asset registry.
            "/api/search-suggest" | "/v1/search-suggest" => {
                let q = target.split('?').nth(1).unwrap_or("");
                let mut query = String::new();
                for kv in q.split('&') {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    if k == "q" {
                        query = pct_decode(v).to_lowercase();
                    }
                }
                let descs = crate::dsol::listed_descriptors();
                let items: Vec<String> = descs
                    .iter()
                    .filter(|c| {
                        c.symbol.to_lowercase().contains(&query)
                            || c.name.to_lowercase().contains(&query)
                    })
                    .map(|c| {
                        format!(
                            r#"{{"symbol":"{}","name":"{}","id":"{}","logo":"{}"}}"#,
                            c.symbol,
                            c.name,
                            c.id.to_hex(),
                            c.logo.to_hex()
                        )
                    })
                    .collect();
                let body = format!(r#"{{"results":[{}]}}"#, items.join(","));
                Some(HttpResponse::json(200, "OK", &body))
            }
            // IonSwap AMM pools — the genesis USDm pairs (wBTC/wETH/wDAI), node-computed with value-hiding
            // committed reserves (pool total stays private). Each pool carries a `locked` flag that drives
            // the 🔒 icon, and ZERO participant identity/linkage.
            "/api/pools" | "/v1/pools" => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            // One pool's detail — id + `locked` state (the UI reads `locked` to show the lock icon). Any
            // `/api/pools/<id>` that is not a sub-resource (e.g. `/chart`) returns the pool.
            // Live chart — the pool's bounded ring of TRANSPARENT trade ticks (buy/sell + amount + price),
            // ZERO identity. This is exactly the user's model: "the chart can show buy and sell amounts for
            // tokens but not WHO is buying or selling." Empty until the pool has traded (no fabricated ticks).
            // ⛔⛔⛔ NO PER-TRADE VOLUME. This served every trade's `amount`, `out` and `price_micro` in
            // cleartext (measured live 2026-08-26). Per-trade amounts ARE volume metadata, which
            // [[feedback_digital_cash_pillar]] bans at every layer — "the chart can show buy and sell
            // amounts" was a misreading of that pillar, because on a constant-product curve a published
            // amount also discloses the pool's depth and every other holder's position by inference.
            // The event ring is deleted with the simulator that fed it; a settled-trade chart, when it
            // returns, must be derived from consensus-public facts alone and carry no per-trade amount.
            p if p.starts_with("/api/pools/") && p.ends_with("/chart") => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            p if p.starts_with("/api/pools/") && !p.contains("/chart") => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            "/api/swap/quote" | "/v1/swap/quote" => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            p if p.starts_with("/api/pool/") => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            // ── Ion Swap: per-pool NETFLOW IS NOT PUBLISHED, and the honest answer says so.
            //    This route used to serve {"netflow":"0","buy":"0","sell":"0"} under a comment claiming the DEX
            //    was a constant-product AMM with no resting orders. Both halves are wrong now: the pool AMM was
            //    retired at source and the DEX is an on-book model of pre-authorised ZK limit orders. A zero is
            //    not a truthful answer for a book that exists — it is an invented measurement.
            //    It is NOT replaced by a real figure: a window's buy/sell flow is exactly the volume metadata
            //    [[feedback_digital_cash_pillar]] bans (the same reason the per-trade chart was deleted on 8/26 —
            //    on a curve, an amount also discloses depth). Callers that need the book to build a fill read
            //    the LEVELS instead, whose served shape is constant by construction.
            //    DIGITAL-CASH-PRIVACY-REVIEWED: publishes no amount, count, volume or timing — it declines, and
            //    names where the legitimate read lives.
            p if p == "/api/orders/netflow" || p == "/v1/orders/netflow" => Some(HttpResponse::json(
                200,
                "OK",
                r#"{"published":false,"reason":"volume_is_not_published","detail":"Per-pool flow (buy/sell/netflow over a window) is trade-volume metadata and is never published. To build a fill, read the order book levels: POST /api/orders/book with {asset_a, asset_b, level} — the served shape is constant, so a busy level and an untouched one answer alike.","read":"/api/orders/book"}"#,
            )),
            // ⛔ RETIRED SURFACE (user ruling 2026-08-26) — this listed the seeded AMM pairs as
            // "mining pools"; the pool AMM is deleted at source, so no invented pair may be advertised.
            "/api/mining/pools" | "/v1/mining/pools" => Some(HttpResponse::json(503, "RETIRED", "{\"status\":\"RETIRED\",\"error\":\"the pool AMM is retired (a pool is shared mutable state that no pillar-safe design could keep); the DEX is being rebuilt as peer-to-peer ZK limit orders and this surface will serve REAL market data when the order book exists — it will never again serve seeded numbers\"}")),
            // ── ION SWAP: MINING STATS — the node's own chain progress, nothing invented. ─────────────
            // This route 404'd on the launch path: the Mining page was written against the retired Express
            // backend and the chain-is-the-backend move ported the PAGE and not its server. It is a READ,
            // so it needs no chain object — it needs the node's real numbers instead of a server's memory.
            // DIGITAL-CASH-PRIVACY-REVIEWED: every field here is already public in /get_info (chain
            // progress and the anti-spam difficulty). No amount, holder, count of real spends or timing of
            // any user's action is exposed; a miner learns what the chain looks like, never who did what.
            p if p == "/api/mining/stats" || p == "/v1/mining/stats" => {
                // ⛔ no node ⇒ UNAVAILABLE, never zeros (surface census 2026-10-04: this route answered 200 with height 0
                // and peers 0 when the loopback RPC was down — a synthetic chain state served as if measured)
                let Some(info) = loopback_rpc_body("/get_info") else { return Some(rpc_unavailable()) };
                let n = |k: &str| json_u64(&info, k).unwrap_or(0);
                let body = format!(
                    r#"{{"height":{},"blue_score":{},"finalized_height":{},"dag_width":{},"proving_power":{},"tips":{},"peers":{}}}"#,
                    n("height"), n("blue_score"), n("finalized_height"),
                    n("dag_width"), n("proving_power"), n("tips"), n("peers")
                );
                Some(HttpResponse::json(200, "OK", &body))
            }

            // ── ION SWAP: STATE ROOT — what a client verifies against. ────────────────────────────────
            // Also 404'd. The page's merkle-verify path needs the roots the node actually holds; serving
            // anything else would be a client verifying against a number this server made up, which is
            // worse than not verifying at all.
            // DIGITAL-CASH-PRIVACY-REVIEWED: roots are commitments — they are what the chain publishes so
            // that holdings need not be. Serving them reveals no value, identity, linkage or amount.
            p if p == "/api/state/root" || p == "/v1/state/root" => {
                // ⛔ no node ⇒ UNAVAILABLE, never an empty root (this handler's own comment: a client verifying against a
                // number this server made up is worse than not verifying at all — and that is what height 0 / "" was)
                let Some(info) = loopback_rpc_body("/get_info") else { return Some(rpc_unavailable()) };
                let sfield = |k: &str| -> String {
                    json_str_field_local(&info, k).unwrap_or_default()
                };
                let body = format!(
                    r#"{{"height":{},"account_root":"{}","unspent_root":"{}"}}"#,
                    json_u64(&info, "height").unwrap_or(0),
                    sfield("account_root"),
                    sfield("unspent_root")
                );
                Some(HttpResponse::json(200, "OK", &body))
            }

            // ── Ion Swap: YIELD vaults — the reserve-yield the node pays on staked USDm, from the LIVE governance
            //    APR (node-computed; the reserve backs it, no inflation). Zero participant identity. ──
            p if p.starts_with("/api/yield") || p.starts_with("/v1/yield") => {
                // ⛔ no node ⇒ UNAVAILABLE: the APR is the LIVE governance value or nothing — the chain default served as
                // "live" was a synthetic answer (surface census 2026-10-04)
                let Some(gov) = loopback_rpc_body("/get_governance") else { return Some(rpc_unavailable()) };
                let Some(apr_bps) = json_u64(&gov, "stake_reward_apr_bps") else { return Some(rpc_unavailable()) };
                let body = format!(
                    r#"{{"apr_bps":{apr_bps},"asset":"USDm","model":"reserve-yield","vaults":[{{"name":"USDm Reserve Yield","asset":"USDm","apr_bps":{apr_bps}}}]}}"#
                );
                Some(HttpResponse::json(200, "OK", &body))
            }
            // ── Explorer: token LOGO — a deterministic, content-addressed SVG coin generated from the symbol
            //    (node-computed; image/svg+xml so the <img> renders inline). Zero external asset, zero VPS. ──
            p if p.starts_with("/api/token-logo/") => {
                let sym: String = p
                    .trim_start_matches("/api/token-logo/")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect();
                // SATOSHI: the native token's real logo (the user's painting, PNG); every other symbol keeps its
                // deterministic generated SVG coin
                if sym.eq_ignore_ascii_case("SAT") {
                    return Some(HttpResponse {
                        status: 200,
                        reason: "OK",
                        content_type: "image/png".to_string(),
                        body: crate::satoshi::LOGO_PNG.to_vec(),
                        site_root: None,
                    veil: None,
                    });
                }
                // ⭐ THE NATIVE COINS' OWN MARKS, FROM THE CHAIN'S OWN SOFTWARE (user 2026-11-10: "the real logos must be
                // chain based ... the correct logo automatically anywhere on chain"). Every node carries the same
                // bytes and serves them here, so the wallet, IonSwap and the explorer show one logo for a coin and
                // none of them ships its own copy. FOUND that day: this route drew a GENERATED coin for Bitcoin and
                // Monero, and the wallet drew MoneroUSD's logo beside every asset that was not BTC or SAT.
                if let Some(mark) = native_coin_mark(&sym) {
                    return Some(HttpResponse {
                        status: 200,
                        reason: "OK",
                        content_type: "image/svg+xml; charset=utf-8".to_string(),
                        body: mark.to_vec(),
                        site_root: None,
                    veil: None,
                    });
                }
                Some(HttpResponse {
                    status: 200,
                    reason: "OK",
                    content_type: "image/svg+xml; charset=utf-8".to_string(),
                    body: token_logo_svg(&sym).into_bytes(),
                    site_root: None,
                    veil: None,
                })
            }
            // ── Explorer: single-token metadata `/api/tokens/{id}` (NOT the exact /api/tokens/verified list, which
            //    is handled above). Match the id against the registry's content-addressed ids or the symbol; an
            //    unknown/blank id returns a VALID found:false — never a 404 (the explorer renders "unknown token"). ──
            p if p.starts_with("/api/tokens/") && p != "/api/tokens/verified" => {
                let id = p.trim_start_matches("/api/tokens/");
                let descs = crate::dsol::listed_descriptors();
                match descs
                    .iter()
                    .find(|c| c.id.to_hex() == id || c.symbol.eq_ignore_ascii_case(id))
                {
                    Some(c) => Some(HttpResponse::json(
                        200,
                        "OK",
                        &format!(
                            r#"{{"found":true,"id":"{}","symbol":"{}","name":"{}","kind":"{}","version":{},"verified":{},"logo":"{}"}}"#,
                            c.id.to_hex(),
                            c.symbol,
                            c.name,
                            c.kind.as_str(),
                            c.version,
                            c.verified,
                            c.logo.to_hex()
                        ),
                    )),
                    None => Some(HttpResponse::json(200, "OK", r#"{"found":false}"#)),
                }
            }
            _ => None,
        }
    }

    /// Node-COMPUTED write endpoints: a create (token / NFT collection) that the node answers by producing
    /// a deterministic DSOL v2 contract — the node's OWN DSOL compiler emits canonical v2 bytecode with a
    /// blake3 content-address (Pillar C: the node is the backend, no VPS, no static file). The returned
    /// artifact is exactly what the wallet broadcasts as a deploy tx (the on-chain append to the unbounded
    /// no-growth registry). Same request → same id (deterministic). Fail-closed on a missing symbol. POST
    /// only. Symbol/name are TYPE metadata (discoverable), never a holder's balance — pillar-safe.
    fn native_write_api(&self, method: &str, target: &str, body: &str) -> Option<HttpResponse> {
        if method != "POST" {
            return None;
        }
        let path = target.split(['?', '#']).next().unwrap_or("");

        // --- MoneroUSD IDE: node-first DSOL contract COMPILE + DEPLOY (Pillar C) ---
        // The node's OWN DSOL v2 assembler turns the editor's source into REAL deployable bytecode (blake3
        // content-addressed id); deploy appends it to the node's live deployed-contract accumulator (an
        // unbounded no-growth MMR — count increments, root advances: a real, observable state change). Source
        // rides `?source=` (pct-encoded), same convention as create's params. Fail-closed on empty/invalid.
        // LETTER (private P2P messaging) — the write side (seal / send / open). The tx-node (:27780) holds the PQ
        // crypto + relay ring; parse the query params, forward as JSON over loopback, return its answer. Only the
        // OPAQUE sealed blob is ever relayed — no plaintext, no classical crypto, no recipient/volume metadata.
        if path == "/api/letter/seal" {
            let q = target.split('?').nth(1).unwrap_or("");
            let (mut to, mut msg) = (String::new(), String::new());
            for kv in q.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                match k {
                    "to" => to = pct_decode(v),
                    "msg" => msg = pct_decode(v),
                    _ => {}
                }
            }
            let jbody = format!(
                r#"{{"to":"{}","msg":"{}"}}"#,
                json_escape_ascii(&to),
                json_escape_ascii(&msg)
            );
            return Some(match loopback_rpc_post("/letter/seal", &jbody) {
                Some(b) if b.trim_start().starts_with('{') => {
                    HttpResponse::json(200, "OK", b.trim())
                }
                _ => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node unreachable for letter seal"}"#,
                ),
            });
        }
        // TESTNET note-forwarder (dev tool) — write side. `drip` forwards value the tool HOLDS to a requester (or
        // its demo key when `to` is absent, so the node can self-verify the landed balance); `receive` takes custody
        // of an off-tree confidential note. Both loopback to the tx-node (:27780), which hard-gates the network.
        if path == "/api/faucet/drip" {
            // ⛔ THE PAGE POSTS A JSON BODY — READ IT. This route parsed `to`/`amount` from the QUERY STRING
            // only, while the faucet page sends `JSON.stringify({amount, to})` as the body. The two never
            // agreed, so `to` was ALWAYS empty here and the node answered BAD_RECIPIENT for every wallet on
            // every attempt — which the page then reported as "That address is invalid", sending users to
            // re-check a perfectly good address. Query string stays supported for direct/manual callers.
            let q = target.split('?').nth(1).unwrap_or("");
            let (mut to, mut amount) = (String::new(), String::new());
            for kv in q.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                match k {
                    "to" => to = pct_decode(v),
                    "amount" => amount = v.chars().filter(|c| c.is_ascii_digit()).collect(),
                    _ => {}
                }
            }
            if let Some(v) = json_str_field_local(body, "to") {
                if !v.is_empty() {
                    to = v;
                }
            }
            if let Some(v) = json_num_field_local(body, "amount") {
                amount = v;
            }
            let jbody = format!(
                r#"{{"to":"{}","amount":{}}}"#,
                json_escape_ascii(&to),
                if amount.is_empty() {
                    "0".into()
                } else {
                    amount
                }
            );
            return Some(match loopback_rpc_post("/faucet/drip", &jbody) {
                Some(b) if b.trim_start().starts_with('{') => {
                    HttpResponse::json(200, "OK", b.trim())
                }
                _ => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node unreachable for faucet drip"}"#,
                ),
            });
        }
        if path == "/api/faucet/receive" {
            let q = target.split('?').nth(1).unwrap_or("");
            let mut note = String::new();
            for kv in q.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                if k == "note" {
                    note = pct_decode(v);
                }
            }
            let jbody = format!(r#"{{"note":"{}"}}"#, json_escape_ascii(&note));
            return Some(match loopback_rpc_post("/faucet/receive", &jbody) {
                Some(b) if b.trim_start().starts_with('{') => {
                    HttpResponse::json(200, "OK", b.trim())
                }
                _ => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node unreachable for faucet receive"}"#,
                ),
            });
        }
        if path == "/api/letter/send" || path == "/api/letter/open" {
            let q = target.split('?').nth(1).unwrap_or("");
            let mut blob = String::new();
            for kv in q.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                if k == "blob" {
                    blob = pct_decode(v);
                }
            }
            let node_path = if path == "/api/letter/send" {
                "/letter/send"
            } else {
                "/letter/open"
            };
            let jbody = format!(r#"{{"blob":"{}"}}"#, json_escape_ascii(&blob));
            return Some(match loopback_rpc_post(node_path, &jbody) {
                Some(b) if b.trim_start().starts_with('{') => {
                    HttpResponse::json(200, "OK", b.trim())
                }
                _ => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"status":"UNAVAILABLE","error":"node unreachable for letter"}"#,
                ),
            });
        }
        if path == "/api/dc/compile" || path == "/api/dc/deploy" {
            let q = target.split('?').nth(1).unwrap_or("");
            let mut source = String::new();
            for kv in q.split('&') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                if k == "source" || k == "src" || k == "code" {
                    source = pct_decode(v);
                }
            }
            if source.trim().is_empty() {
                return Some(HttpResponse::json(
                    400,
                    "Bad Request",
                    r#"{"ok":false,"error":"source required"}"#,
                ));
            }
            let compiled = match crate::dsol::compile_source(&source) {
                Ok(c) => c,
                Err(e) => {
                    return Some(HttpResponse::json(
                        400,
                        "Bad Request",
                        // the compiler's message may quote the offending token (the IDE needs it): bounded to 160 chars, so a
                        // 16 KB body is never reflected back whole (surface census 2026-10-04)
                        &format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape_ascii(&e.chars().take(160).collect::<String>())),
                    ));
                }
            };
            let bytecode_hex: String = compiled
                .bytecode
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if path == "/api/dc/compile" {
                let body = format!(
                    r#"{{"ok":true,"id":"{}","version":{},"kind":"generic","size":{},"bytecode":"{}"}}"#,
                    compiled.id.to_hex(),
                    compiled.version,
                    compiled.bytecode.len(),
                    bytecode_hex
                );
                return Some(HttpResponse::json(200, "OK", &body));
            }
            // deploy: register the compiled contract into the node's LIVE deployed-DSOL accumulator (real state change).
            let contract = crate::dsol::DsolContract {
                id: compiled.id,
                version: compiled.version,
                kind: compiled.kind,
                symbol: compiled.symbol.clone(),
                name: compiled.name.clone(),
                verified: false,
                logo: Hash32::default(),
            };
            let mut reg = self.deployed.lock().unwrap_or_else(|e| e.into_inner());
            let index = reg.register(&contract);
            let count = reg.count();
            let root = reg.root_bytes();
            drop(reg);
            let root_hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
            let body = format!(
                r#"{{"ok":true,"id":"{}","version":{},"registered":true,"index":{},"registryCount":{},"registryRoot":"{}","size":{}}}"#,
                compiled.id.to_hex(),
                compiled.version,
                index,
                count,
                root_hex,
                compiled.bytecode.len()
            );
            return Some(HttpResponse::json(200, "OK", &body));
        }

        // ⛔⛔⛔ A SETTLEMENT THIS SERVER CANNOT SETTLE IS REFUSED, NEVER SIMULATED.
        //
        // This route once mutated an in-process seeded curve and answered `"ok":true` for fills that
        // moved no value (the measured 572,491→50 drain of the fund-safety audit). It failed closed from
        // then on — and the POOL ITSELF is now retired at source (user ruling 2026-08-26: a pool is
        // shared mutable state no pillar-safe design could keep). The DEX is being rebuilt as
        // peer-to-peer ZK limit orders; a swap will be a taker's one-transaction fill of a maker's
        // resting order, and THIS route will never issue a fill.
        // ── ION SWAP → THE AUDITED ON-CHAIN ORDER PATH. The shipped orders page posts here; without these
        //    two arms the request fell through to a 404 and the order button did nothing. Both forward the
        //    caller's body verbatim to the tx-node over loopback and hand back the node's own answer, so
        //    every gate that protects a fill runs where it always did — in the node, never here:
        //    /post_order (expiry, proof, self-deal, owner-present, payout-note binding, atomic pair-burn)
        //    and /book_level (a constant served shape, so polling reveals neither depth nor activity).
        //    This server verifies nothing and stores nothing: it is a same-origin hop to our own node.
        // ── ION SWAP: MINT AND BURN — value moves, so the NODE decides, not this server. ─────────────
        // These 404'd on the launch path: the pages were written against the retired Express backend and
        // the chain-is-the-backend move ported the PAGES and not their server. They move real value, so
        // the only correct implementation forwards to the node's own gated routes — /wrapped_mint_execute
        // refuses unless the note's commitment opens to the AUTHORISED amount in the AUTHORISED asset, and
        // the peg routes carry their own gates. This server verifies nothing and stores nothing; it is a
        // same-origin hop, and the verdict the caller sees is the node's own.
        // Ion Swap's quote client POSTs JSON `{op, asset, amount}` (sites/ionswap-monerousd-org/lib/mint-burn-client.js); only the
        // GET form was served, so the app's quote never reached the node (surface census 2026-10-04). One answer, both forms.
        // ⭐ SPEC §12.6 — THE MARKETPLACE'S FOUR READS, for a page this node serves with no wallet connected: this node's
        // OWN copy of the chain's directory (an asset's record and picture, a collection and its pieces, the collections
        // list). Exactly the four public routes, named here one by one; nothing else under `/dir/` is reachable from a
        // page. They are reads of what creators published; nothing is written and nothing is asked of another node.
        if let Some(route) = path.strip_prefix("/api/market/") {
            if matches!(route, "asset" | "asset_art" | "collection" | "collections") {
                return Some(match loopback_rpc_post(&["/dir/", route].concat(), body) {
                    Some(b) => HttpResponse::json(200, "OK", &b),
                    None => rpc_unavailable(),
                });
            }
        }
        if path == "/api/mint-burn/quote" || path == "/v1/mint-burn/quote" {
            let op = json_str_field_local(body, "op").unwrap_or_else(|| "mint".into());
            let asset = json_str_field_local(body, "asset").unwrap_or_default();
            let amount = json_str_field_local(body, "amount").unwrap_or_default();
            return Some(mint_burn_quote(&op, &asset, &amount));
        }
        if path == "/api/mint-burn/mint" || path == "/v1/mint-burn/mint" {
            return Some(match loopback_rpc_post("/wrapped_mint_execute", body) {
                Some(b) => HttpResponse::json(200, "OK", &b),
                None => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"ok":false,"error":"node_unreachable","detail":"The local node did not answer /wrapped_mint_execute. NOTHING was minted."}"#,
                ),
            });
        }
        if path == "/api/mint-burn/burn" || path == "/v1/mint-burn/burn" {
            return Some(match loopback_rpc_post("/peg_out_execute", body) {
                Some(b) => HttpResponse::json(200, "OK", &b),
                None => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"ok":false,"error":"node_unreachable","detail":"The local node did not answer /peg_out_execute. NOTHING was burned."}"#,
                ),
            });
        }
        if path == "/api/bridge/wrap/create" || path == "/v1/bridge/wrap/create" {
            return Some(match loopback_rpc_post("/peg_in_execute", body) {
                Some(b) => HttpResponse::json(200, "OK", &b),
                None => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"ok":false,"error":"node_unreachable","detail":"The local node did not answer /peg_in_execute. NO wrap was created."}"#,
                ),
            });
        }

        if path == "/api/orders/submit" || path == "/v1/orders/submit" {
            return Some(match loopback_rpc_post("/post_order", body) {
                Some(b) => HttpResponse::json(200, "OK", &b),
                None => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"ok":false,"error":"node_unreachable","detail":"The local node did not answer /post_order. The order was NOT posted."}"#,
                ),
            });
        }
        if path == "/api/orders/book" || path == "/v1/orders/book" {
            return Some(match loopback_rpc_post("/book_level", body) {
                Some(b) => HttpResponse::json(200, "OK", &b),
                None => HttpResponse::json(
                    503,
                    "Service Unavailable",
                    r#"{"ok":false,"error":"node_unreachable","detail":"The local node did not answer /book_level."}"#,
                ),
            });
        }
        if path == "/api/swap/create" || path == "/v1/swap/create" {
            return Some(HttpResponse::json(
                503,
                "Service Unavailable",
                r#"{"ok":false,"error":"pool_amm_retired","detail":"The pool AMM is retired. The DEX is moving to peer-to-peer ZK limit orders: a swap settles as one on-chain transaction filling a resting order, built by the wallet. No off-chain fill is issued and no pool exists to mutate."}"#,
            ));
        }
        // ⛔ LP LOCK / WITHDRAW ARE REMOVED. Both mutated pool state for ANY anonymous caller: a lock from
        // a stranger permanently blocked the real LP's exit (measured live on wETH). LP positions belong
        // on chain with an owner, so these return the honest reason rather than an unauthenticated write.
        if path.starts_with("/api/pools/")
            && (path.ends_with("/lock") || path.ends_with("/withdraw"))
        {
            return Some(HttpResponse::json(
                503,
                "Service Unavailable",
                r#"{"ok":false,"error":"lp_position_is_onchain","detail":"Liquidity positions are consensus state owned by a wallet. This server performs no unauthenticated pool mutation."}"#,
            ));
        }

        // ⛔⛔⛔ §BR-14 (2026-10-28) — THIS ROUTE CREATED NOTHING AND CHARGED A FEE ANY NOTE COULD PAY TWICE. It compiled a
        // descriptor and returned JSON (no chain object), after checking only that a caller-supplied note OPENS to the price
        // — nothing spent that note, so one note "paid" for every creation, and the id it returned was derived without a
        // creator (no asset the chain would ever register under it). Creating an asset is a chain transaction the creator's
        // wallet builds, signs and PAYS (`window.monerousd.createToken` → `/submit_asset_create`, whose creation carries a
        // real burn of the price, `asset_tx::CreationFee`). Deleted at source; the route answers where creation lives.
        if path == "/api/tokens/create" || path == "/api/nft/order" {
            return Some(HttpResponse::json(
                410,
                "Gone",
                r#"{"ok":false,"error":"creation_is_a_wallet_transaction","detail":"Creating a token or NFT is a chain transaction your wallet signs and pays (window.monerousd.createToken). This server creates nothing and charged nothing."}"#,
            ));
        }
        None
    }

    pub fn serve(self: Arc<Self>, port: u16) -> std::io::Result<()> {
        let v4 = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
        // Best-effort IPv6 loopback too: a client that dials `localhost` may resolve it to `::1` first
        // (common on macOS). Binding only 127.0.0.1 makes those connections refuse+retry = a real
        // slowness source; bind both so `localhost` and `127.0.0.1` are equally instant.
        if let Ok(v6) = std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)) {
            let me6 = Arc::clone(&self);
            std::thread::spawn(move || {
                for stream in v6.incoming().flatten() {
                    let me = Arc::clone(&me6);
                    std::thread::spawn(move || {
                        let _ = me.handle_conn(stream);
                    });
                }
            });
        }
        for stream in v4.incoming().flatten() {
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.handle_conn(stream);
            });
        }
        Ok(())
    }

    fn handle_conn(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        let (head, mut prebody) = match read_request_head(&mut stream) {
            Some(x) => x,
            None => return Ok(()),
        };
        let first = head.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("/").to_string();

        // ⛔ DB-374: only the user's own software reaches this server. A rebinding page's host name is refused on
        // every request; a foreign WRITE is refused; the wallet's cross-site FRAMING of a public site (a GET/HEAD
        // navigation with no Origin) is admitted — a site's public bytes reveal nothing, and `frame-ancestors` already
        // names who may embed it. A refusal is answered 403 before any endpoint runs. No response carries a CORS
        // header (the apps are same-origin; the wallet reaches this server through its own Rust proxy), so no other
        // origin can read an answer.
        let from = crate::local_origin::RequestOrigin::from_head(&head);
        let read_only = method == "GET" || method == "HEAD";
        // ⭐ ISOLATED REALM ASSETS (2026-10-28, hole scanner T1). A site's vendored library (three.js, Monaco) runs in a
        // sandboxed frame with an OPAQUE origin, so that realm's own `import` of its module files arrives as a CORS read
        // with `Origin: null`. Those files are the site's public static bytes and nothing else: a GET/HEAD of a path under
        // a vendored directory from `Origin: null` is admitted and answered with `Access-Control-Allow-Origin: null`, so
        // the realm can run them. NOTHING ELSE changes: an API path, a site document or any write from `Origin: null`
        // stays refused (DB-374), and no answer but a realm asset's ever carries a CORS header
        // (`a_realm_asset_is_readable_from_an_opaque_origin_and_nothing_else_is`).
        let realm_asset = read_only && from.origin.as_deref() == Some("null") && is_realm_asset_path(&target);
        let refused: Option<HttpResponse> = if realm_asset {
            None
        } else {
            match crate::local_origin::admit(&from, read_only) {
                Ok(_) => None,
                Err(why) => Some(HttpResponse::json(403, "Forbidden", &format!("{{\"status\":\"FORBIDDEN\",\"error\":\"{why}\"}}"))),
            }
        };

        // Node-COMPUTED endpoints first (chain height from the live DAG tip): the node computes that
        // slice of the backend directly (Pillar C) — no proxy, no daemon, no VPS.
        if let Some(resp) = refused.or_else(|| self.native_api(&method, &target)) {
            stream.write_all(&resp.to_bytes(method == "HEAD"))?;
            return stream.flush();
        }
        // Node-COMPUTED WRITE endpoints (a create/compile): the node answers with a deterministic,
        // deployable DSOL v2 contract (blake3-addressed bytecode) from its own DSOL compiler — real
        // node-first, no VPS/mock. The wallet broadcasts the returned artifact as the on-chain deploy tx.
        // ⛔ DRAIN THE REQUEST BODY BEFORE DISPATCH. `read_request_head` returns only the body bytes that
        // happened to ride the SAME TCP read as the head, so a body in a second segment was silently lost. A PQ
        // receive address is ~1.7 KB, so this is the common case, not the edge case.
        let req_body = {
            let want = header_value(&head, "content-length")
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            // ⛔ BOUNDED WORK AT THE ONE INGRESS (surface census 2026-10-04, every write route at once): a body declared
            // or streamed above `rpc_http::RPC_BODY_MAX` is refused 413 BEFORE a byte more is read and before any
            // endpoint runs. The write routes forward their body to the loopback RPC, which refuses above the same cap,
            // so a larger body can never be legitimate here; without this, `Content-Length: 10^12` grew `prebody`
            // without bound (T3 exhaustion). cons: none — the cap is the RPC's own.
            if want > crate::rpc_http::RPC_BODY_MAX || prebody.len() > crate::rpc_http::RPC_BODY_MAX {
                let resp = HttpResponse::json(
                    413,
                    "Payload Too Large",
                    r#"{"status":"REFUSED","error":"request body above the door's cap"}"#,
                );
                stream.write_all(&resp.to_bytes(false))?;
                return stream.flush();
            }
            while prebody.len() < want {
                let mut chunk = [0u8; 8192];
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => prebody.extend_from_slice(&chunk[..n]),
                }
            }
            String::from_utf8_lossy(&prebody).to_string()
        };
        if let Some(resp) = self.native_write_api(&method, &target, &req_body) {
            stream.write_all(&resp.to_bytes(false))?;
            return stream.flush();
        }
        // Other dynamic dApp-backend paths (/api/*, /v1/*, /events, /ws) reverse-proxy SAME-ORIGIN to
        // the node-local backend over loopback — the node IS the backend (Pillar C), never a VPS.
        // Static chain-anchored assets are served directly.
        if let Some(up) = &self.api_upstream {
            if is_api_path(&target) {
                return self.proxy(up, &head, &mut prebody, &mut stream);
            }
        }
        let mut resp = self.respond(&method, &target);
        // SUBPATH ASSET RE-RESOLUTION: a site served under `/<site>/` whose bundle requests a ROOT-ABSOLUTE
        // asset (`/app.js`, `/logo.svg`, `/assets/…`) would miss at the node root. The browser sends a
        // `Referer: …/<site>/…` on those sub-resource loads, so when a static GET/HEAD 404s at root we retry
        // it under the referring site. This makes the ported bundles work as-is under the sovereign mount
        // (no bundle rewrite), and only ever re-resolves to a REAL hosted-site asset (else the retry 404s too).
        if resp.status == 404 && (method == "GET" || method == "HEAD") {
            if let Some(site) = referer_site(&head) {
                let sub = if target.starts_with('/') {
                    target.clone()
                } else {
                    format!("/{target}")
                };
                if !sub.starts_with(&format!("/{site}/")) {
                    let retry = format!("/{site}{sub}");
                    let r2 = self.respond(&method, &retry);
                    if r2.status != 404 {
                        resp = r2;
                    }
                }
            }
        }
        let bytes = resp.to_bytes(method == "HEAD");
        stream.write_all(&if realm_asset && resp.status == 200 { with_realm_cors(bytes) } else { bytes })?;
        stream.flush()
    }

    /// Reverse-proxy one request to the loopback dApp backend. Plain requests stream the response back
    /// verbatim (we force `Connection: close` so the body terminates at EOF); a WebSocket upgrade
    /// switches to a bidirectional byte relay (live price/order streams). Backend down → 502 (never a
    /// VPS fallback). The upstream is loopback-guarded at config time, so this never leaves the machine.
    fn proxy(
        &self,
        upstream: &str,
        head: &str,
        prebody: &mut Vec<u8>,
        client: &mut TcpStream,
    ) -> std::io::Result<()> {
        let content_length = header_value(head, "content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let is_upgrade = header_value(head, "upgrade")
            .map(|v| v.to_ascii_lowercase().contains("websocket"))
            .unwrap_or(false);

        // Drain any request body beyond what arrived with the head.
        let mut body = std::mem::take(prebody);
        while body.len() < content_length {
            let mut chunk = [0u8; 8192];
            match client.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }

        let mut up = match TcpStream::connect(upstream) {
            Ok(s) => s,
            Err(_) => {
                let r = HttpResponse::text(
                    502,
                    "Bad Gateway",
                    "<h1>502</h1><p>node-local backend unavailable (no VPS fallback by design)</p>",
                );
                client.write_all(&r.to_bytes(false))?;
                return client.flush();
            }
        };
        let fwd_head = if is_upgrade {
            head.to_string()
        } else {
            rewrite_connection_close(head)
        };
        up.write_all(fwd_head.as_bytes())?;
        up.write_all(b"\r\n\r\n")?;
        up.write_all(&body)?;
        up.flush()?;

        if is_upgrade {
            // Live stream: relay bytes both directions until either side closes. No idle timeout.
            let _ = up.set_read_timeout(None);
            let _ = client.set_read_timeout(None);
            duplex_relay(client, &mut up)
        } else {
            let _ = up.set_read_timeout(Some(Duration::from_secs(60)));
            let mut chunk = [0u8; 8192];
            loop {
                match up.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client.write_all(&chunk[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            client.flush()
        }
    }
}

impl Default for SovereignServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Recursively read every file under `dir` into an [`Asset`] whose path is relative to `root`.
/// A file's stamp, read from its metadata.
fn file_stamp(m: &std::fs::Metadata) -> FileStamp {
    (m.len(), m.modified().ok())
}

/// Every file's stamp under a site folder, keyed exactly as [`collect_assets`] keys its assets.
// O1-INFINITY-REVIEWED: a site folder's static web files (a dApp's pages), never chain state; the same folder `collect_assets` already reads at start
fn collect_stamps(root: &Path, dir: &Path, out: &mut HashMap<String, FileStamp>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_stamps(root, &path, out)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let key = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
            out.insert(key, file_stamp(&std::fs::metadata(&path)?));
        }
    }
    Ok(())
}

fn collect_assets(root: &Path, dir: &Path, out: &mut Vec<Asset>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_assets(root, &path, out)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            // Bundle paths are absolute-from-site-root with forward slashes: "/index.html".
            let mut asset_path = String::from("/");
            asset_path.push_str(&rel.to_string_lossy().replace('\\', "/"));
            let bytes = std::fs::read(&path)?;
            out.push(Asset {
                path: asset_path.clone(),
                content_type: content_type_for(&asset_path),
                bytes,
            });
        }
    }
    Ok(())
}

/// 32 bytes → 64-char lowercase hex.
fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One IonSwap AMM pool as JSON: a `token`/USDm pair. The pool's reserves are value-hiding Poseidon
/// COMMITMENTS (its total liquidity stays private — the digital-cash pillar); the DEX market activity
/// (buy/sell + amounts on the chart) is the transparent, UNLINKABLE surface. `locked` drives the 🔒 icon.
/// The pool id + token id are content-addressed. Carries ZERO participant identity/linkage.
fn pool_json_for(token_id: &Hash32, sym: &str, logo_hex: &str, locked: bool) -> String {
    let usdm_r = crate::dsol::commit_u64(
        0,
        format!("USDMD-POOL-USDM:{}", token_id.to_hex()).as_bytes(),
    );
    let tok_r = crate::dsol::commit_u64(
        0,
        format!("USDMD-POOL-TOK:{}", token_id.to_hex()).as_bytes(),
    );
    let pool_id = Hash32::hash(format!("USDMD-POOL-v1:{}", token_id.to_hex()).as_bytes());
    format!(
        r#"{{"id":"{}","token_id":"{}","symbol":"{}","logo":"{}","usdm_reserve_commit":"{}","token_reserve_commit":"{}","locked":{}}}"#,
        pool_id.to_hex(),
        token_id.to_hex(),
        json_escape_ascii(sym),
        logo_hex,
        hex32(&usdm_r),
        hex32(&tok_r),
        locked
    )
}

/// The node's internal constant-product curve `(x, y)` for a pool — `x` the USDm side, `y` the token side,
/// deterministic per symbol. These price a swap (`x*y=k`); the pool's ON-WIRE reserves stay value-hiding
/// commitments (the pool total is private), so a quote returns ONLY the caller's own output, never the
/// pool depth or anyone else's position. A fresh pool starts near-balanced; the token side jitters per
/// symbol so pools differ.
/// Extract an unsigned integer field from a node JSON body by key — the same string-JSON convention the rest of
/// the sovereign surface uses (no serde dependency on this hot loopback path). Returns None if the key is absent.
fn json_u64(body: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let idx = body.find(&pat)? + pat.len();
    let rest = body[idx..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse::<u64>().ok()
}

/// A deterministic, content-addressed coin logo for a token symbol — node-COMPUTED (blake3(sym) → color + the
/// full ticker), so the explorer's `<img src=/api/token-logo/SYM>` always renders inline with zero external asset,
/// zero VPS, and identical bytes for the same symbol on every node (Pillar C).
fn token_logo_svg(sym: &str) -> String {
    let h = blake3::hash(format!("USDMD-TOKEN-LOGO:{sym}").as_bytes());
    let b = h.as_bytes();
    let (r, g, bl) = (b[0], b[1], b[2]);
    let label: String = if sym.is_empty() {
        "?".into()
    } else {
        sym.to_string()
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64"><circle cx="32" cy="32" r="30" fill="rgb({r},{g},{bl})"/><circle cx="32" cy="32" r="30" fill="none" stroke="rgba(255,255,255,0.25)" stroke-width="2"/><text x="32" y="39" font-family="system-ui,Arial,sans-serif" font-size="16" font-weight="700" fill="#fff" text-anchor="middle" textLength="44" lengthAdjust="spacingAndGlyphs">{label}</text></svg>"##
    )
}

/// The node's live confidential AMM. Keyed by UPPERCASE symbol; an unknown/alias key (e.g. the harness's
/// `DEMO`) resolves to the flagship pool so every pool op targets a real curve.

/// Sanitize a short display string to ASCII-alphanumeric so it is JSON-injection-safe.
/// Minimal JSON string-body escaper: escapes the characters JSON forbids unescaped (`"`, `\`, and the
/// control chars below 0x20) and passes ALL other printable ASCII through verbatim — so legitimate
/// spaces, hyphens and punctuation in a symbol/name/error survive intact. Non-ASCII bytes are dropped
/// (every caller here emits ASCII). Prevents JSON injection without mangling real content.
fn json_escape_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {}
            c if c.is_ascii() => out.push(c),
            _ => {}
        }
    }
    out
}

/// Parse a 64-char hex string into a `Hash32` content-address; any malformed / wrong-length input yields
/// the all-zero hash (= "no logo"). Fail-closed: a bad hex never fabricates a partial hash.
/// Decode a hex field into bytes. An odd-length or non-hex field yields EMPTY, which every caller
/// treats as "absent" and refuses — a partially-decoded fee note must never read as a payment.
/// The ONE canonical form of a token symbol. The price quote and the enforcing gate both call this, so
/// a symbol can never be quoted at one length and charged at another.
fn canonical_symbol(raw: &str) -> String {
    raw.chars().filter(char::is_ascii_alphanumeric).collect()
}

/// Atomic USDm rendered for display (1e8 atomic = 1 USDm), trailing zeros trimmed.
fn format_atomic_usdm(atomic: u64) -> String {
    let whole = atomic / 100_000_000;
    let frac = atomic % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    format!("{whole}.{:08}", frac).trim_end_matches('0').to_string()
}

/// A basis-point rate rendered as a percentage string for display ("10" bps -> "0.1").
fn format_bps_pct(bps: u64) -> String {
    let whole = bps / 100;
    let frac = bps % 100;
    if frac == 0 {
        return whole.to_string();
    }
    format!("{whole}.{:02}", frac).trim_end_matches('0').to_string()
}

/// A native coin's own mark, compiled into every node (the one copy; the apps read it from `/api/token-logo/<SYM>`).
/// A wrapped name answers with its coin's mark. Any other symbol has none here and gets the generated coin.
/// O1-FOOTPRINT-REVIEWED: six fixed files compiled into the binary, a few hundred bytes to 1.5 KB each; nothing grows.
fn native_coin_mark(sym: &str) -> Option<&'static [u8]> {
    let s = sym.to_ascii_uppercase();
    let coin = s.strip_prefix('W').filter(|c| matches!(*c, "BTC" | "XMR" | "ETH" | "ZEC" | "SOL")).unwrap_or(&s);
    Some(match coin {
        "BTC" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/BTC.svg") as &[u8],
        "XMR" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/XMR.svg") as &[u8],
        "ETH" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/ETH.svg") as &[u8],
        "ZEC" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/ZEC.svg") as &[u8],
        "SOL" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/SOL.svg") as &[u8],
        "USDM" => include_bytes!("../sites/ionswap-monerousd-org/assets/coins/USDm.svg") as &[u8],
        _ => return None,
    })
}

#[cfg(test)]
mod native_coin_mark_tests {
    use super::*;

    /// Every native coin answers with ITS OWN mark (an SVG that is not the generated coin and not another coin's), a
    /// wrapped name answers with its coin's, and a made-up symbol still gets the generated coin and never a real one.
    #[test]
    fn each_native_coin_is_served_its_own_mark_and_no_other_symbol_borrows_one() {
        let s = SovereignServer::new();
        let logo = |sym: &str| s.native_api("GET", &format!("/api/token-logo/{sym}")).expect("the logo route answers").body;
        let coins = ["BTC", "XMR", "ETH", "ZEC", "SOL", "USDm"];
        let marks: Vec<Vec<u8>> = coins.iter().map(|c| logo(c)).collect();
        for (i, m) in marks.iter().enumerate() {
            assert!(String::from_utf8_lossy(m).contains("<svg"), "{} is an SVG", coins[i]);
            assert_ne!(*m, token_logo_svg(coins[i]).into_bytes(), "{} is not the generated coin", coins[i]);
            for (j, other) in marks.iter().enumerate() {
                assert!(i == j || m != other, "{} and {} share a mark", coins[i], coins[j]);
            }
        }
        assert_eq!(logo("wBTC"), marks[0], "a wrapped name shows its coin");
        assert_eq!(logo("btc"), marks[0], "whatever the case");
        assert_eq!(logo("MOON"), token_logo_svg("MOON").into_bytes(), "a symbol with no mark gets the generated coin");
        assert_eq!(logo("WHALE"), token_logo_svg("WHALE").into_bytes(), "a symbol that merely starts with W borrows nothing");
        assert_eq!(logo("SAT"), crate::satoshi::LOGO_PNG.to_vec());
    }
}

/// The name of what a quoted price is for, so a client labels what it displays without a second copy of the rule.
fn create_fee_kind_name(nft: bool) -> &'static str {
    if nft { "nft" } else { "token" }
}

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    let t = s.trim();
    if t.is_empty() || t.len() % 2 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let b = t.as_bytes();
    for i in (0..b.len()).step_by(2) {
        match u8::from_str_radix(core::str::from_utf8(&b[i..i + 2]).unwrap_or("zz"), 16) {
            Ok(v) => out.push(v),
            Err(_) => return Vec::new(),
        }
    }
    out
}

fn parse_hash32_hex(s: &str) -> Hash32 {
    if s.len() != 64 {
        return Hash32::ZERO;
    }
    let mut b = [0u8; 32];
    for i in 0..32 {
        match u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
            Ok(x) => b[i] = x,
            Err(_) => return Hash32::ZERO,
        }
    }
    Hash32::from_slice(&b).unwrap_or(Hash32::ZERO)
}

/// Percent-decode a URL query value (`%20`→space, `+`→space). Used by the node-computed write endpoints
/// to read a create's symbol/name from the query string. Malformed escapes are kept verbatim.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Extract the FIRST path segment of the request's `Referer` header — i.e. the hosted-site dir the page that
/// issued this sub-resource request was loaded from (`Referer: http://127.0.0.1:27752/ide-monerousd-org/…`
/// → `ide-monerousd-org`). Used to re-resolve a bundle's root-absolute asset (`/app.js`) under its own site.
fn referer_site(head: &str) -> Option<String> {
    let line = head.lines().find(|l| {
        let lo = l.to_ascii_lowercase();
        lo.starts_with("referer:") || lo.starts_with("referrer:")
    })?;
    let url = line.splitn(2, ':').nth(1)?.trim();
    // Skip `scheme://host/`, take the first path segment.
    let path = url.splitn(4, '/').nth(3)?; // ["http:", "", "host", "seg/rest…"]
    let seg = path.split(['/', '?', '#']).next()?;
    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
}

/// Read the full HTTP request HEAD (everything up to CRLFCRLF) plus any body bytes that arrived in the
/// same read. Returns `(head_without_trailing_crlfcrlf, leftover_body_bytes)`.
/// Read a JSON string field out of a request body. The sovereign server has no JSON parser linked, and these
/// routes only ever need one flat scalar each — the node re-parses the canonical body it is handed.
fn json_str_field_local(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)? + pat.len();
    let rest = body.get(i..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Read a JSON numeric field (digits only) out of a request body.
fn json_num_field_local(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)? + pat.len();
    let rest = body.get(i..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn read_request_head(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let body = buf[pos + 4..].to_vec();
            return Some((head, body));
        }
        if buf.len() > 65536 {
            break;
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some((String::from_utf8_lossy(&buf).to_string(), Vec::new()))
    }
}

/// Dynamic dApp-backend paths that reverse-proxy to the node-local backend (everything else is a
/// static, chain-anchored site asset). Kept in sync with the Ion Swap frontend's `apiBase` surface.
fn is_api_path(path: &str) -> bool {
    let p = path.split(['?', '#']).next().unwrap_or("");
    p.starts_with("/api/")
        || p == "/api"
        || p.starts_with("/v1/")
        || p == "/v1"
        || p.starts_with("/events")
        || p.starts_with("/ws")
        || p.starts_with("/rpc/")
        || p.starts_with("/socket.io")
}

/// A backend upstream MUST be loopback (same-machine) — never a routable/VPS host (Pillar C.3). Guards
/// [`SovereignServer::set_api_upstream`] so the sovereign path can never be pointed at an operator.
fn is_loopback_authority(auth: &str) -> bool {
    let host = match auth.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest), // [::1]:port
        None => auth.rsplit_once(':').map(|(h, _)| h).unwrap_or(auth),
    };
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

/// Rewrite the request head to force `Connection: close` (drop client keep-alive), so the upstream
/// closes after responding and our verbatim relay terminates at EOF.
fn rewrite_connection_close(head: &str) -> String {
    let mut out = String::with_capacity(head.len() + 20);
    for (i, line) in head.split("\r\n").enumerate() {
        let low = line.to_ascii_lowercase();
        if i > 0 && (low.starts_with("connection:") || low.starts_with("proxy-connection:")) {
            continue;
        }
        if !out.is_empty() {
            out.push_str("\r\n");
        }
        out.push_str(line);
    }
    out.push_str("\r\nConnection: close");
    out
}

/// Case-insensitive lookup of a request header value from the head (skips the request line).
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    let name_low = name.to_ascii_lowercase();
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == name_low {
                return Some(v.trim());
            }
        }
    }
    None
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Relay bytes bidirectionally between two streams until either closes (WebSocket proxy).
fn duplex_relay(a: &mut TcpStream, b: &mut TcpStream) -> std::io::Result<()> {
    let (mut a2, mut b2) = (a.try_clone()?, b.try_clone()?);
    let t = std::thread::spawn(move || {
        let _ = copy_stream(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let _ = copy_stream(b, a);
    let _ = a.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    Ok(())
}

fn copy_stream(from: &mut TcpStream, to: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n])?;
    }
    Ok(())
}

/// True if the last path segment has a file extension (`foo.js` → true, `/route/deep` → false).
fn last_segment_has_ext(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|seg| seg.contains('.'))
        .unwrap_or(false)
}

/// Serve the hosted sites on loopback `port`, with `/api/chain-tip` mirroring the canonical height the local node
/// reports on its own loopback RPC. One bring-up for every host of the sites: the desktop's `serve-sites` process
/// and a phone's in-process host (a phone cannot spawn a second process, so while this lived only in `main.rs` a
/// phone had no site host at all and every launchpad app pointed at a dead port). The node is found by
/// `loopback_tx_node_port`, the one rule every node-backed route here already follows. Blocks for the life of
/// the server. Loopback only, like `serve`: nothing here opens a routable socket, and nothing is kept on disk.
pub fn serve_mirroring_tip(mut server: SovereignServer, port: u16) -> std::io::Result<()> {
    let tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let tip = Arc::clone(&tip);
        std::thread::spawn(move || loop {
            // The canonical GHOSTDAG height ("blue_score") from the real node's own `/get_info`.
            if let Some(body) = loopback_rpc_body("/get_info") {
                if let Some(i) = body.find("\"blue_score\":") {
                    let digits: String = body[i + 13..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(h) = digits.parse::<u64>() {
                        tip.store(h, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1_000));
        });
    }
    server.set_chain_tip(tip);
    Arc::new(server).serve(port)
}

/// Map a bundle path's extension to a Content-Type (the merkle leaf binds this type, so a client
/// cannot be served the right bytes under a wrong type).
pub fn content_type_for(path: &str) -> String {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let ct = match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "map" => "application/json; charset=utf-8",
        "txt" | "md" => "text/plain; charset=utf-8",
        "wat" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    ct.to_string()
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn asset(path: &str, ct: &str, bytes: &[u8]) -> Asset {
        Asset {
            path: path.into(),
            content_type: ct.into(),
            bytes: bytes.to_vec(),
        }
    }

    fn server_with_ionswap() -> SovereignServer {
        let mut s = SovereignServer::new();
        s.host_site(
            "ionswap-monerousd-org",
            vec![
                asset(
                    "/index.html",
                    "text/html; charset=utf-8",
                    b"<!doctype html><title>Ion Swap</title><h1>Ion Swap</h1>",
                ),
                asset(
                    "/app.js",
                    "text/javascript; charset=utf-8",
                    b"console.log('ion swap')",
                ),
                asset("/styles.css", "text/css; charset=utf-8", b"body{margin:0}"),
                asset(
                    "/lib/swap-client.js",
                    "text/javascript; charset=utf-8",
                    b"export const swap=1",
                ),
            ],
        )
        .unwrap();
        s.host_site(
            "explorer-monerousd-org",
            vec![asset(
                "/index.html",
                "text/html; charset=utf-8",
                b"<h1>Explorer</h1>",
            )],
        )
        .unwrap();
        s
    }

    #[test]
    fn node_first_index_is_served_2xx() {
        let s = server_with_ionswap();
        // This is EXACTLY what the wallet's Ion Swap launcher probes: GET /<dir>/ must be 2xx.
        let r = s.respond("GET", "/ionswap-monerousd-org/");
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/html"));
        assert!(String::from_utf8_lossy(&r.body).contains("Ion Swap"));
        // The chain-anchored root is exposed so a client can authenticate the bytes against consensus.
        assert!(r.site_root.is_some());
    }

    #[test]
    fn nested_asset_served_with_correct_type() {
        let s = server_with_ionswap();
        let r = s.respond("GET", "/ionswap-monerousd-org/lib/swap-client.js");
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/javascript"));
        assert_eq!(r.body, b"export const swap=1");
    }

    #[test]
    fn unknown_site_and_missing_file_404() {
        let s = server_with_ionswap();
        assert_eq!(s.respond("GET", "/no-such-dapp/").status, 404);
        // A real missing FILE (has an extension) 404s...
        assert_eq!(
            s.respond("GET", "/ionswap-monerousd-org/missing.js").status,
            404
        );
        // ...but an extension-less deep link falls back to index.html (SPA client-side routing).
        assert_eq!(
            s.respond("GET", "/ionswap-monerousd-org/some/route").status,
            200
        );
    }

    #[test]
    fn directory_index_lists_hosted_dapps() {
        let s = server_with_ionswap();
        let r = s.respond("GET", "/");
        assert_eq!(r.status, 200);
        let body = String::from_utf8_lossy(&r.body);
        assert!(body.contains("ionswap-monerousd-org"));
        assert!(body.contains("explorer-monerousd-org"));
    }

    #[test]
    fn non_get_rejected() {
        let s = server_with_ionswap();
        assert_eq!(s.respond("POST", "/ionswap-monerousd-org/").status, 405);
        assert_eq!(s.respond("DELETE", "/ionswap-monerousd-org/").status, 405);
    }

    #[test]
    fn served_bytes_authenticate_against_chain_root() {
        // The uncensorability guarantee: a client re-derives the site root from the served bytes +
        // proof and it MATCHES the anchored root; a tampered byte would fail. Here we prove the serve
        // path is sound end to end (server self-verifies; a client would use the same verify_served).
        let s = server_with_ionswap();
        let sites = s.read_sites();
        let site = sites.get("ionswap-monerousd-org").unwrap();
        let served = site.bundle.serve("/index.html").unwrap();
        assert!(site::verify_served(&site.root, "/index.html", &served));
        // Tamper one byte → verification MUST fail (fail-closed).
        let mut bad = served;
        bad.bytes[0] ^= 0xff;
        assert!(!site::verify_served(&site.root, "/index.html", &bad));
    }

    /// ⛔ STALE-SITE CLASS — the host serves what its folder holds NOW: a changed file, an added file and a removed file are
    /// each seen on the next request (MEASURED 2026-11-12: a 24-day-old host served the IonSwap pages it read at start).
    /// TWO-PARTY-REVIEWED: the two sides are the folder a deploy writes and the host that reads it; both are real here (the
    /// files on disk and the server's own request path), and the wallet's page is the third party measured by `web3-connect`.
    /// LOCAL-STORAGE-REQUIRED: the test IS a deploy writing a site folder (the thing under test is a host reading one); no
    /// proof or wire field stands in for a web page on disk. bound: three files under 64 bytes in the OS temp dir, removed.
    #[test]
    fn stale_site_the_host_serves_what_its_folder_holds_now() {
        let base = std::env::temp_dir().join(format!("sovereign-stale-{}", std::process::id()));
        let site_dir = base.join("demo-site");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&site_dir).unwrap();
        std::fs::write(site_dir.join("index.html"), b"<title>old</title>").unwrap();
        let mut s = SovereignServer::new();
        s.load_all(&base).unwrap();
        assert_eq!(s.respond("GET", "/demo-site/").body, b"<title>old</title>".to_vec(), "CALIBRATION: the first read");
        let root_before = s.root_of("demo-site");
        // a deploy rewrites the page (a different length, so the stamp differs whatever the clock's resolution)
        std::fs::write(site_dir.join("index.html"), b"<title>new release</title>").unwrap();
        assert_eq!(s.respond("GET", "/demo-site/").body, b"<title>new release</title>".to_vec(), "⛔ the host served the page it read at start");
        assert_ne!(s.root_of("demo-site"), root_before, "the reloaded site has its own root");
        // a file added after start is served, and its bytes still authenticate against the bundle root
        std::fs::write(site_dir.join("pools.js"), b"export const pools = 1;").unwrap();
        let added = s.respond("GET", "/demo-site/pools.js");
        assert_eq!((added.status, added.body), (200, b"export const pools = 1;".to_vec()), "⛔ a file added after start is not served");
        // a file removed is no longer served
        std::fs::remove_file(site_dir.join("pools.js")).unwrap();
        assert_eq!(s.respond("GET", "/demo-site/pools.js").status, 404, "⛔ a removed file is still served");
        // a site hosted from anywhere but the folder is never replaced by the folder
        s.host_site("demo-site", vec![Asset { path: "/index.html".into(), content_type: "text/html".into(), bytes: b"pinned".to_vec() }]).unwrap();
        assert_eq!(s.respond("GET", "/demo-site/").body, b"pinned".to_vec(), "⛔ a hosted (not folder) site was overwritten from disk");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn api_paths_route_to_backend_not_static() {
        // The dApp-backend surface reverse-proxies; everything else is a static site asset.
        assert!(is_api_path("/api/tokens"));
        assert!(is_api_path("/api/swap/quote?a=1"));
        assert!(is_api_path("/v1/prices"));
        assert!(is_api_path("/ws"));
        assert!(is_api_path("/events"));
        assert!(!is_api_path("/ionswap-monerousd-org/"));
        assert!(!is_api_path("/ionswap-monerousd-org/app.js"));
        assert!(!is_api_path("/"));
    }

    #[test]
    fn upstream_must_be_loopback_no_vps() {
        let mut s = SovereignServer::new();
        // loopback upstreams accepted...
        s.set_api_upstream(Some("127.0.0.1:7787".into()));
        assert_eq!(s.api_upstream(), Some("127.0.0.1:7787"));
        s.set_api_upstream(Some("localhost:7787".into()));
        assert_eq!(s.api_upstream(), Some("localhost:7787"));
        s.set_api_upstream(Some("[::1]:7787".into()));
        assert_eq!(s.api_upstream(), Some("[::1]:7787"));
        // ...a routable/VPS upstream is REJECTED (no phone-home backend, Pillar C.3).
        s.set_api_upstream(Some("ion.monerousd.org:443".into()));
        assert_eq!(s.api_upstream(), None);
        s.set_api_upstream(Some("203.0.113.7:7787".into()));
        assert_eq!(s.api_upstream(), None);
    }

    #[test]
    fn connection_close_is_forced_on_forward() {
        let head = "GET /api/tokens HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nAccept: */*";
        let rw = rewrite_connection_close(head);
        assert!(rw.contains("GET /api/tokens HTTP/1.1"));
        assert!(rw.contains("Accept: */*"));
        assert!(rw.ends_with("Connection: close"));
        assert!(!rw.to_ascii_lowercase().contains("keep-alive"));
        // header_value reads a header case-insensitively.
        assert_eq!(header_value(head, "content-length"), None);
        assert_eq!(
            header_value("POST /x HTTP/1.1\r\nContent-Length: 42", "content-length"),
            Some("42")
        );
    }

    #[test]
    fn chain_tip_is_node_computed_from_live_dag() {
        let mut s = SovereignServer::new();
        // No live node wired → chain-tip is NOT natively handled (it proxies / 404s); never a synthetic
        // height. This is what keeps the endpoint honest when there is no producer.
        assert!(s.native_api("GET", "/api/chain-tip").is_none());
        // Wire the live DAG-tip blue-score (as the producer loop does) → served natively from the real
        // value, no daemon / VPS / C++ wallet-rpc.
        let tip = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        s.set_chain_tip(std::sync::Arc::clone(&tip));
        tip.store(42, std::sync::atomic::Ordering::Relaxed);
        let r = s
            .native_api("GET", "/api/chain-tip")
            .expect("chain-tip served from the live tip");
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("application/json"));
        assert!(String::from_utf8_lossy(&r.body).contains("\"height\":42"));
        // The v1 alias has the same shape; a non-GET is not natively handled.
        assert!(s.native_api("GET", "/v1/chain-tip").is_some());
        assert!(s.native_api("POST", "/api/chain-tip").is_none());
        // A path we don't natively compute falls through to the proxy (returns None here). NOTE: `/api/tokens` used
        // to be the example, but it is now NATIVELY served (the real DSOL token-registry list), so the fall-through
        // must be demonstrated with a route that genuinely has no native handler.
        assert!(s.native_api("GET", "/api/not-a-native-route").is_none());
    }

    #[test]
    fn content_type_mapping() {
        assert!(content_type_for("/a.wasm").starts_with("application/wasm"));
        assert!(content_type_for("/a.js").starts_with("text/javascript"));
        assert!(content_type_for("/a.css").starts_with("text/css"));
        assert!(content_type_for("/a.html").starts_with("text/html"));
        assert_eq!(content_type_for("/a.bin"), "application/octet-stream");
    }

    #[test]
    fn head_omits_body_keeps_length() {
        let s = server_with_ionswap();
        let r = s.respond("GET", "/ionswap-monerousd-org/");
        let head_bytes = r.to_bytes(true);
        let full_bytes = r.to_bytes(false);
        let head_str = String::from_utf8_lossy(&head_bytes);
        assert!(head_str.contains(&format!("Content-Length: {}", r.body.len())));
        assert!(full_bytes.len() > head_bytes.len()); // full carries the body, HEAD does not
                                                      // CSP + no-referrer present so a served page cannot phone home.
        assert!(head_str.contains("Content-Security-Policy:"));
        assert!(head_str.contains("Referrer-Policy: no-referrer"));
    }

    /// THE SERVED PAGE REACHES TWO PLACES AND NO OTHER: this host, and the MonerousD wallet's connect door on this same
    /// computer. A third host in `connect-src`, or a door on a routable address, would let a served page send its
    /// user's activity out; a policy without the door leaves the node-served copy unable to reach its user's wallet
    /// from an ordinary browser (measured 2026-11-10: `connect-src 'self'` blocked exactly that).
    /// TWO-PARTY-REVIEWED: this pins the WORDS of one header this host sends, which has one side. The crossing it
    /// permits (a page served by this host, in a browser, reaching the wallet's door in another process) is run with
    /// the real site host, the real wallet core and real nodes by `scratchpad/net/web3_connect.py`.
    #[test]
    fn the_served_page_may_reach_this_host_and_the_wallets_door_and_nothing_else() {
        let s = server_with_ionswap();
        let head = String::from_utf8_lossy(&s.respond("GET", "/ionswap-monerousd-org/").to_bytes(true)).to_string();
        let csp = head.lines().find(|l| l.starts_with("Content-Security-Policy:")).expect("the host sends a policy");
        let connect = csp.split(';').map(str::trim).find(|d| d.starts_with("connect-src")).expect("the policy names what a page may reach");
        assert_eq!(connect, "connect-src 'self' http://127.0.0.1:27751", "a served page may reach something other than this host and the wallet's door");
        assert!(csp.contains("default-src 'self'"), "everything else stays on this host");
    }

    /// The mint/burn quote answers the app's POST JSON and the GET query identically, by canonical ticker, and refuses an
    /// unknown asset, a non-numeric amount and an unknown op (400) instead of quoting zero or echoing the input.
    #[test]
    fn the_mint_burn_quote_answers_the_apps_post_and_the_get_alike_and_refuses_what_it_does_not_serve() {
        let s = SovereignServer::new();
        let post = s.native_write_api("POST", "/api/mint-burn/quote", r#"{"op":"mint","asset":"btc","amount":"150"}"#).expect("POST is served");
        let get = s.native_api("GET", "/api/mint-burn/quote?dir=mint&asset=BTC&amount=150").expect("GET is served");
        assert_eq!(post.status, 200);
        assert_eq!(post.body, get.body, "one answer for both forms");
        let text = String::from_utf8_lossy(&post.body).to_string();
        assert!(text.contains(r#""asset":"BTC""#) && text.contains(r#""quote":"100""#), "150 at the 150% ratio quotes 100: {text}");
        for (q, why) in [
            ("dir=mint&asset=DOGE&amount=1", "unknown asset"),
            ("dir=mint&asset=BTC&amount=abc", "non-numeric amount"),
            ("dir=steal&asset=BTC&amount=1", "unknown op"),
        ] {
            let r = s.native_api("GET", &format!("/api/mint-burn/quote?{q}")).expect("answered");
            assert_eq!(r.status, 400, "{why} is refused");
        }
    }

    /// ⭐ SURFACE CENSUS (2026-10-04, "bounded work" at the door): a body DECLARED above `rpc_http::RPC_BODY_MAX` is refused
    /// 413 before a byte of it is read — the client here never sends the body, so a door that waited for it would hang
    /// instead of answering. MEASURED before the fix: `handle_conn` read `Content-Length` bytes with no bound.
    #[test]
    fn a_body_declared_above_the_cap_is_refused_at_the_door_before_it_is_read() {
        let s = std::sync::Arc::new(SovereignServer::new());
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            let head = format!(
                "POST /api/faucet/drip HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                1u64 << 40
            );
            c.write_all(head.as_bytes()).unwrap();
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out);
            out
        });
        let (stream, _) = l.accept().unwrap();
        s.handle_conn(stream).unwrap();
        let out = client.join().unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with("HTTP/1.1 413 "),
            "the door refuses an over-cap declaration before reading it: {}",
            text.lines().next().unwrap_or("")
        );
        assert!(text.contains("above the door's cap"));
        assert!(crate::rpc_http::RPC_BODY_MAX >= 4 << 20, "the cap admits every legitimate framed object with its carrier");
    }

    /// ⭐ SURFACE CENSUS (2026-10-04 — the route rows "door answers (proof, conservation, replay, bounded work, privacy of
    /// the answer) unmeasured"): the WHOLE native route table, read and write, answers its door with NO node behind it.
    /// Read routes: a bounded answer that never echoes the query (reflection is how a GET leaks), and a node-backed route
    /// answers 503, never a synthetic value (MEASURED before the fix: `/api/mining/stats` served height 0 / peers 0 and
    /// `/api/state/root` an empty root, both 200). Write routes: an empty, a malformed and a 16 KB garbage body are
    /// refused (≥ 400), never 2xx, never echoed; a GET is not a write. The loopback RPC port is pointed at a CLOSED port
    /// first, so "no node" is the measured condition and no test ever reaches a live node.
    #[test]
    fn every_native_route_answers_its_door_with_no_node_bounded_and_never_a_synthetic_value() {
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        std::env::set_var("MONEROUSD_LOOPBACK_RPC_PORT", closed.to_string());
        assert_eq!(loopback_tx_node_port(), closed);
        assert!(loopback_rpc_body("/get_info").is_none(), "CALIBRATION: the loopback port is closed — no node answers");
        let s = SovereignServer::new();
        let garbage = "Z".repeat(16 * 1024);
        let marker = &garbage[..64];
        // (route, node-backed: its honest answer needs the node)
        let reads: [(&str, bool); 25] = [
            ("/", false),
            ("/_directory", false),
            ("/_directory/", false),
            ("/api/chain-tip", false),
            ("/api/config", false),
            ("/api/dsol/asset-classes", false),
            ("/api/dsol/manifest", false),
            ("/api/dsol/registry-root", false),
            ("/api/explorer/assets", false),
            ("/api/explorer/dag-recent", true),
            ("/api/explorer/takeover-cost", true),
            ("/api/faucet/identity", true),
            ("/api/faucet/status", true),
            ("/api/letter/identity", true),
            ("/api/letter/inbox", true),
            ("/api/letter/scan", true),
            ("/api/mining/pools", false),
            ("/api/mining/stats", true),
            ("/api/mint-burn/quote", false),
            ("/api/orders/netflow", false),
            ("/api/prices", false),
            ("/api/reserves", true),
            ("/api/search-suggest", false),
            ("/api/state/root", true),
            ("/api/yield", true),
        ];
        for (route, node_backed) in reads {
            for target in [route.to_string(), format!("{route}?q={garbage}&amount={garbage}&asset={marker}")] {
                let r = if route == "/" || route.starts_with("/_") { Some(s.respond("GET", &target)) } else { s.native_api("GET", &target) };
                let Some(r) = r else { continue }; // not natively served here (chain-tip without a wired tip): the proxy / 404 door
                let text = String::from_utf8_lossy(&r.body).to_string();
                assert!(r.body.len() <= 1 << 20, "{route}: a bounded answer ({} B)", r.body.len());
                assert!(!text.contains(marker), "{route}: the answer echoes the query");
                if node_backed {
                    assert!(
                        r.status >= 400,
                        "{route}: with no node the answer is a refusal, never a synthetic value — got {} {}",
                        r.status,
                        text.chars().take(160).collect::<String>()
                    );
                }
                assert!(s.native_api("POST", &target).is_none(), "{route}: a POST is not a read");
            }
        }
        let writes = [
            "/api/bridge/wrap/create",
            "/api/dc/compile",
            "/api/dc/deploy",
            "/api/faucet/drip",
            "/api/faucet/receive",
            "/api/letter/open",
            "/api/letter/seal",
            "/api/letter/send",
            "/api/mint-burn/burn",
            "/api/mint-burn/mint",
            "/api/nft/order",
            "/api/orders/book",
            "/api/orders/submit",
            "/api/swap/create",
            "/api/tokens/create",
        ];
        for route in writes {
            for body in ["", "{", "not json", garbage.as_str()] {
                for target in [route.to_string(), format!("{route}?symbol={marker}&source={marker}&to={marker}")] {
                    if let Some(r) = s.native_write_api("POST", &target, body) {
                        let text = String::from_utf8_lossy(&r.body).to_string();
                        assert!(
                            r.status >= 400,
                            "{route}: body {:?}… with no node is refused, never applied — got {} {}",
                            &body[..body.len().min(8)],
                            r.status,
                            text.chars().take(160).collect::<String>()
                        );
                        if route.starts_with("/api/dc/") {
                            // a compiler error may quote the offending token for the developer — bounded, never the body
                            assert!(r.body.len() <= 512, "{route}: a compiler error is bounded ({} B)", r.body.len());
                        } else {
                            assert!(r.body.len() <= 1 << 20, "{route}: a bounded answer");
                            assert!(!text.contains(marker), "{route}: the answer echoes the body or the query");
                        }
                    }
                    assert!(s.native_write_api("GET", &target, body).is_none(), "{route}: a GET is not a write");
                }
            }
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod token_creation_fee_gate_tests {
    //! ⛔⛔⛔ §BR-14 (2026-10-28) — THE WEB ROUTE'S "FEE" WAS A NOTE ANYONE COULD MINT A PROOF FOR. Its gate checked that a
    //! caller's note OPENS to the price (`verify_asset_mint_validity_bytes`), and that proof needs no ownership: the pin that
    //! stood here proved an "honest fee note" by calling the prover with a made-up key, and it PAID. Nothing spent the note
    //! either, and the route created nothing on chain. Creation is now a chain transaction that burns the price
    //! (`asset_tx::CreationFee`, pinned at `asset_tx::tests::br14_*`); this route answers where creation lives.

    use super::*;

    /// ⛔ THE ROUTE CREATES NOTHING AND TAKES NOTHING — for a token and an NFT, with no fee and with the self-minted "fee
    /// note" the old gate accepted (the replay case): every answer is 410 and names the wallet transaction.
    #[test]
    fn the_web_create_route_creates_nothing_and_points_at_the_paid_chain_transaction() {
        let required = crate::params::token_create_fee_atomic("MOONSHOT");
        let sk = usdm_decider::poseidon2_compress::lanes_of(&[41, 43, 47, 53]);
        let (carrier, cm) = usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(
            required,
            usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            &sk,
        )
        .expect("CALIBRATION: anyone can prove a note opens to the price — that is why it was never a payment");
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let srv = SovereignServer::new();
        for target in [
            "/api/tokens/create?symbol=MOONSHOT&name=Moon".to_string(),
            "/api/nft/order?symbol=PUNKS&name=Punks".to_string(),
            format!("/api/tokens/create?symbol=MOONSHOT&name=Moon&fee_note={}&fee_carrier={}", hex(&note), hex(&carrier)),
        ] {
            let r = srv.native_write_api("POST", &target, "").expect("the route answers");
            let body = String::from_utf8_lossy(&r.body);
            assert_eq!(r.status, 410, "{target}: the web route creates nothing — got {} {body}", r.status);
            assert!(body.contains("creation_is_a_wallet_transaction") && body.contains("createToken"), "names where creation lives: {body}");
            assert!(!body.contains("\"id\""), "and returns no asset id it never created: {body}");
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod create_fee_quote_tests {
    //! ⛔⛔⛔ THE QUOTE AND THE CHARGE MUST BE THE SAME NUMBER. A client that computes its own price
    //! drifts the moment either side moves — that is not hypothetical, it is the measured defect this
    //! route replaces: a "Creation Bond" of 10,000 / 2,500 / 500 USDm displayed over a route that
    //! charged nothing, mirroring a `backend/tokens/create.js` that no longer exists.

    use super::*;

    fn quote(symbol: &str) -> String {
        let r = SovereignServer::new()
            .native_api("GET", &format!("/api/tokens/create_fee?symbol={symbol}"))
            .expect("the quote route answers");
        assert_eq!(r.status, 200);
        String::from_utf8_lossy(&r.body).to_string()
    }

    /// ⭐⭐⭐ THE QUOTE EQUALS WHAT THE GATE DEMANDS — checked against the REFUSAL, which is the number
    /// actually enforced. If these two ever diverge, this test fails rather than a user overpaying.
    #[test]
    fn every_tier_quotes_exactly_what_the_gate_refuses_below() {
        // an NFT's quote is the NFT gate's price, asked with `kind=nft`, and it is not the token's
        let nft_quote = String::from_utf8_lossy(&SovereignServer::new().native_api("GET", "/api/tokens/create_fee?symbol=OWL001&kind=nft").expect("the quote route answers").body).to_string();
        let nft_gate = crate::asset_tx::AssetCreateTx {
            kind: crate::asset_tx::AssetKind::Nft,
            symbol: "OWL001".into(),
            name: String::new(),
            logo: [0u8; 32],
            bytecode: Vec::new(),
            creator: [0u8; 32],
            asset_id: [0u8; 32],
            fee: crate::asset_tx::CreationFee::default(),
            art: Vec::new(),
            supply: None,
        }
        .creation_price();
        assert!(nft_quote.contains(&format!("\"fee_atomic\":{nft_gate}")) && nft_quote.contains("\"tier\":\"nft\""), "{nft_quote}");
        assert_ne!(nft_gate, crate::params::token_create_fee_atomic("OWL001"), "CALIBRATION: the two kinds are priced apart");
        for sym in ["A", "AB", "ABC", "MOON", "MOONS", "MOONSHOT", "AVERYLONGSYMBOL"] {
            let q = quote(sym);
            // RE-MEASURED 2026-11-10: this pin asked the WEB create route for a 402 naming the fee, and since §BR-14
            // (2026-10-28) that route creates nothing and charges nothing (410, `token_creation_fee_gate_tests`): the
            // gate that charges is the chain's own: the fee the creation transaction itself carries and burns when a
            // block applies it (`AssetCreateTx::creation_price`, pinned at `asset_tx::tests::br14_*`). The pin read RED
            // from that day. What it protects is unchanged: the number the
            // quote shows is the number the gate charges, one function for both.
            let refusal = SovereignServer::new()
                .native_write_api("POST", &format!("/api/tokens/create?symbol={sym}"), "")
                .expect("the create route answers");
            assert_eq!(refusal.status, 410, "{sym}: the web route creates nothing and charges nothing");
            let enforced = crate::params::token_create_fee_atomic(sym);
            assert!(enforced > 0, "{sym}: CALIBRATION: creation has a price, or the comparison below is of zeros");
            assert!(q.contains(&format!("\"fee_atomic\":{enforced}")), "{sym}: quote said {q}");
            let charged = crate::asset_tx::AssetCreateTx {
                kind: crate::asset_tx::AssetKind::Token,
                symbol: sym.to_string(),
                name: String::new(),
                logo: [0u8; 32],
                bytecode: Vec::new(),
                creator: [0u8; 32],
                asset_id: [0u8; 32],
                fee: crate::asset_tx::CreationFee::default(),
                art: Vec::new(),
                supply: None,
            }
            .creation_price();
            assert_eq!(charged, enforced, "{sym}: the chain's creation gate charges what the quote shows");
        }
    }

    /// ⛔ THE QUOTE CANONICALIZES THE SYMBOL THE WAY THE GATE DOES. `MO-ON` is five raw characters and
    /// four real ones; quoting the raw length would under- or over-charge by a whole tier.
    #[test]
    fn punctuation_cannot_split_the_quote_from_the_charge() {
        let dirty = quote("MO-ON");
        let clean = quote("MOON");
        assert!(dirty.contains("\"symbol\":\"MOON\""), "the quote reports the canonical symbol: {dirty}");
        let n = crate::params::token_create_fee_atomic("MOON").to_string();
        assert!(dirty.contains(&format!("\"fee_atomic\":{n}")), "{dirty}");
        assert!(clean.contains(&format!("\"fee_atomic\":{n}")), "{clean}");
    }

    /// ⭐ THE QUOTE IS SELF-DESCRIBING — amount, human-readable amount, ASSET and tier. A client that has
    /// to infer any of these keeps a second copy of the rules, which is how the fiction started.
    #[test]
    fn the_quote_states_the_asset_and_the_tier_so_no_client_has_to_know_them() {
        let q = quote("MOONSHOT");
        for k in ["\"fee_atomic\":", "\"fee_usdm\":", "\"asset\":\"USDm\"", "\"tier\":\"token\""] {
            assert!(q.contains(k), "missing {k} in {q}");
        }
        // a symbol's length no longer names a tier: every token quote says what it is a price for
        assert!(quote("ABC").contains("\"tier\":\"token\""));
    }

    /// ⭐ THE RATE RENDERS EXACTLY. These strings ARE what a user reads as the price of a trade and of a
    /// redemption, so a rounding slip here is the same class of defect as a wrong rate — smaller print.
    #[test]
    fn the_rendered_rate_matches_the_basis_points_exactly() {
        assert_eq!(format_bps_pct(10), "0.1", "the 10 bps fill fee reads as 0.1%");
        assert_eq!(format_bps_pct(25), "0.25", "the withdraw floor reads as 0.25%");
        assert_eq!(format_bps_pct(9_000), "90", "the withdraw ceiling reads as 90%");
        assert_eq!(format_bps_pct(30), "0.3");
        assert_eq!(format_bps_pct(1), "0.01");
        assert_eq!(format_bps_pct(100), "1");
        assert_eq!(format_bps_pct(10_000), "100");
        assert_eq!(format_bps_pct(0), "0");
        // ⛔ NEVER ROUND A RATE UP OR DOWN INTO A DIFFERENT NUMBER. Every bps value in 0..=10_000 must
        // round-trip back through the string, or some rate somewhere is displayed as a rate it is not.
        for bps in 0..=10_000u64 {
            let shown = format_bps_pct(bps);
            let back = (shown.parse::<f64>().expect("a number") * 100.0).round() as u64;
            assert_eq!(back, bps, "{bps} bps rendered as {shown}, which reads back as {back}");
        }
    }

    /// ⭐ THE HUMAN NUMBER MATCHES THE ATOMIC ONE. A display that rounds differently from the charge is
    /// the same class of lie in smaller print.
    #[test]
    fn the_displayed_amount_is_the_atomic_amount() {
        assert_eq!(format_atomic_usdm(100_000_000_000), "1000");
        assert_eq!(format_atomic_usdm(25_000_000_000), "250");
        assert_eq!(format_atomic_usdm(5_000_000_000), "50");
        assert_eq!(format_atomic_usdm(1_000_000_000), "10");
        assert_eq!(format_atomic_usdm(150_000_000), "1.5");
        assert_eq!(format_atomic_usdm(1), "0.00000001");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod no_hardcoded_fee_rates_in_the_client_tests {
    //! ⛔⛔⛔ A GUARD FOR THE WHOLE CLASS, NOT THE SIX INSTANCES I FOUND.
    //!
    //! MEASURED 2026-09-02, one sweep of `sites/ionswap-monerousd-org`: SEVEN different "fee" rates
    //! displayed to users, no two agreeing, and NONE of them charged by the chain —
    //!
    //!   token-create.js  "traders pay only the 0.30% protocol fee" + a "Pool fee 0.30%" row
    //!   token-create.js  a "Creation Bond" of 10,000 / 2,500 / 500 / 100 USDm + 0.001 USDm per
    //!                    metadata byte, over a route that charged NOTHING
    //!   liquidity.js     "Pool fee 0.05% / 0.30%" and "60% reserves · 30% POL · 10% bounty"
    //!   orders.js        "Match fee 0.20% — you pay 20 bps on fill"
    //!   invoicing.js     "Invoice fee 0.30%"
    //!   dca.js           "Swap fee per fire 0.30%"
    //!   pools.js         a 0.05%/0.30% tier column and "a 50 bps fee ... through the protocol fee split"
    //!   nft-marketplace  a 5-USDm-per-NFT "bulk bond", a "2% resale royalty (50/50)", "60/30/10 routing"
    //!   router-client.js an entire AMM quote engine taking `gross * 997n / 1000n` at UNIT = 1e12
    //!                    (this chain is 1e8) — dead code, wrong scale, imported but never called
    //!
    //! The node charges exactly THREE things: `order_fill_fee_bps`, `token_create_fee_atomic`, and the
    //! peg withdraw band. Everything else above was invented. Fixing the instances is worthless if the
    //! next page can add an eighth, so this walks the shipped client and fails on a fee rate written as
    //! a literal. The rate is CONSENSUS and governance-tunable at runtime: even a literal that is correct
    //! today is a latent lie the moment governance moves it.

    use std::path::{Path, PathBuf};

    fn site_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("sites/ionswap-monerousd-org")
    }

    fn shipped_js() -> Vec<PathBuf> {
        let mut out = Vec::new();
        for sub in ["pages", "lib", "components"] {
            let d = site_dir().join(sub);
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                // Only what actually ships: `.js`. Backups (`.preX-DATE`) and retired files
                // (`.DELETED-…`) keep their original text on purpose as a record of the defect.
                if p.extension().and_then(|x| x.to_str()) == Some("js") {
                    out.push(p);
                }
            }
        }
        out
    }

    /// A line states a RATE if it puts a numeric percentage or bps figure in a fee context.
    fn offending_rate(line: &str) -> bool {
        let l = line.trim();
        // Prose ABOUT the defect is how we remember it — in JS comments and in HTML comments alike.
        // (An HTML comment is not shown to a user, so it cannot mislead one.)
        if l.starts_with("//") || l.starts_with("*") || l.starts_with("///") || l.starts_with("<!--")
        {
            return false;
        }
        let lower = l.to_ascii_lowercase();
        // ⭐ MATCH THE CLAIM, NOT THE CSS CLASS. `fee-row` / `fee-value` are layout names and say
        // nothing about whether a line states a price: `<span class="fee-label">Time jitter</span>
        // <span class="fee-value">±10%</span>` is a timing parameter wearing the fee stylesheet. When
        // the line carries an explicit label, that LABEL decides; only an unlabelled line falls back to
        // scanning the whole text. Same precision rule as hook-invocation-match.py — a guard that fires
        // on a mention instead of the real thing gets routed around, and then it is not a standard.
        let money_word = |t: &str| {
            let t = t.to_ascii_lowercase();
            ["fee", "bps", "royalt", "bond", "commission", "rate", "cost", "charge", "split"]
                .iter()
                .any(|w| t.contains(w))
        };
        if let Some(rest) = lower.split("fee-label\">").nth(1) {
            let label = rest.split("</span>").next().unwrap_or("");
            if !money_word(label) {
                return false;
            }
        } else if !money_word(&lower) {
            return false;
        }
        // "50 bps", "0.30%", "0.05 %" adjacent to a fee word.
        let bytes = l.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                let rest = l[i..].trim_start();
                if rest.starts_with('%') || rest.to_ascii_lowercase().starts_with("bps") {
                    // `${f.pct}%` and friends are template reads, not literals.
                    let before = &l[..start];
                    if !before.ends_with('}') {
                        return true;
                    }
                }
            } else {
                i += 1;
            }
        }
        false
    }

    /// ⛔⛔⛔ NO SHIPPED CLIENT FILE MAY WRITE A FEE RATE AS A LITERAL.
    #[test]
    fn no_page_states_a_fee_rate_the_chain_does_not_report() {
        let mut bad: Vec<String> = Vec::new();
        for f in shipped_js() {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            for (n, line) in text.lines().enumerate() {
                if offending_rate(line) {
                    bad.push(format!(
                        "{}:{} — {}",
                        f.file_name().unwrap_or_default().to_string_lossy(),
                        n + 1,
                        line.trim()
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "a shipped page states a fee rate as a literal. The rate is consensus and \
             governance-tunable — ask the wallet that frames the page (it reads the node's /api/config \
             `orderFillFeeBps` and shows every cost in its own sheet), or say '—' if it has not answered. Offenders:\n  {}",
            bad.join("\n  ")
        );
    }

    /// ⭐ THE DETECTOR ITSELF MUST DISCRIMINATE. A guard that cannot fail is not a guard — this pins
    /// that it catches the exact lines that shipped, and stays quiet on the shapes that are fine.
    #[test]
    fn the_detector_catches_what_actually_shipped_and_spares_what_is_fine() {
        for bad in [
            r#"<span class="fee-value">0.30%</span>"#,
            r#"<div class="fee-row"><span class="fee-label">Match fee</span><span class="fee-value">0.20%</span></div>"#,
            r#"const fee = p.kind === 'stable' ? '0.05%' : '0.30%';"#,
            r#"title="Mint additional supply (up to max_supply, 50 bps fee)""#,
            r#"feeLabel: 'Confidential pool · 0.30%',"#,
            // a labelled money claim is still caught even when the word "fee" is absent from the label
            r#"<div class="fee-row"><span class="fee-label">Royalty on resale</span><span class="fee-value">2%</span></div>"#,
            r#"<div class="fee-row"><span class="fee-label">Mint bond</span><span class="fee-value">10.00 USDm</span> 2%</div>"#,
        ] {
            assert!(offending_rate(bad), "must be caught: {bad}");
        }
        for ok in [
            r#"<span class="fee-value">${f.pct}%</span>"#,
            r#"el.textContent = `${f.pct}% fee`;"#,
            r#"// liquidity.js "Pool fee 0.05% / 0.30%" — the defect, described in prose"#,
            r#"<!-- a "2% resale royalty" was rendered here; nothing enforces it -->"#,
            r#"<option value="100" selected>1.0%</option>"#,       // slippage, no fee word
            r#"<div class="apr">12.5%</div>"#,                     // an APR is not a fee
            // a timing parameter wearing the fee stylesheet — the LABEL decides, not the class name
            r#"<div class="fee-row"><span class="fee-label">Time jitter</span><span class="fee-value">&plusmn;10%</span></div>"#,
            r#"style="width:50%;opacity:0.30""#,                   // layout
        ] {
            assert!(!offending_rate(ok), "must be allowed: {ok}");
        }
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod realm_asset_tests {
    use super::*;

    fn asset(path: &str, ct: &str, bytes: &[u8]) -> Asset {
        Asset { path: path.into(), content_type: ct.into(), bytes: bytes.to_vec() }
    }

    /// ⭐ ISOLATED REALM ASSETS (2026-10-28, hole scanner T1 — vendored scripts). A sandboxed frame has an OPAQUE origin, so
    /// its `import` of a vendored module arrives as `Origin: null`. The door admits exactly that: a GET of a path under
    /// `/vendor/` from `Origin: null` is 200 with `Access-Control-Allow-Origin: null`. The SAME origin asking for the
    /// site's document, a non-vendored module or an API path is refused (DB-374); a write from it is refused; and the same
    /// vendored path asked by the user's own app carries NO CORS header — nothing but a realm asset to an opaque origin does.
    #[test]
    fn a_realm_asset_is_readable_from_an_opaque_origin_and_nothing_else_is() {
        let mut s = SovereignServer::new();
        s.host_site(
            "ide-monerousd-org",
            vec![
                asset("/index.html", "text/html; charset=utf-8", b"<!doctype html><title>IDE</title>"),
                asset("/app.js", "text/javascript; charset=utf-8", b"export const app=1"),
                asset("/vendor/three.module.js", "text/javascript; charset=utf-8", b"export const THREE=1"),
            ],
        )
        .unwrap();
        let s = std::sync::Arc::new(s);
        let ask = |s: &std::sync::Arc<SovereignServer>, method: &str, path: &str, origin: Option<&str>| -> String {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let head = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: 0\r\n\r\n",
                origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default()
            );
            let client = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut c = std::net::TcpStream::connect(addr).unwrap();
                c.write_all(head.as_bytes()).unwrap();
                let mut out = Vec::new();
                let _ = c.read_to_end(&mut out);
                String::from_utf8_lossy(&out).into_owned()
            });
            let (stream, _) = l.accept().unwrap();
            s.handle_conn(stream).unwrap();
            client.join().unwrap()
        };
        let ok = ask(&s, "GET", "/ide-monerousd-org/vendor/three.module.js", Some("null"));
        assert!(ok.starts_with("HTTP/1.1 200 "), "{}", ok.lines().next().unwrap_or(""));
        assert!(ok.contains("Access-Control-Allow-Origin: null\r\n"), "the realm can read its own module: {ok}");
        assert!(ok.ends_with("export const THREE=1"), "the bytes are the site's: {ok}");
        for path in ["/ide-monerousd-org/", "/ide-monerousd-org/index.html", "/ide-monerousd-org/app.js", "/api/get_info"] {
            let r = ask(&s, "GET", path, Some("null"));
            assert!(!r.starts_with("HTTP/1.1 200 "), "⛔ Origin: null read {path}: {}", r.lines().next().unwrap_or(""));
            assert!(!r.contains("Access-Control-Allow-Origin"), "⛔ a CORS header on a refused answer ({path})");
        }
        let post = ask(&s, "POST", "/ide-monerousd-org/vendor/three.module.js", Some("null"));
        assert!(!post.starts_with("HTTP/1.1 200 "), "⛔ a write from the realm was answered");
        assert!(!post.contains("Access-Control-Allow-Origin"), "⛔ a CORS header on a refused write");
        let own = ask(&s, "GET", "/ide-monerousd-org/vendor/three.module.js", None);
        assert!(own.starts_with("HTTP/1.1 200 "), "{}", own.lines().next().unwrap_or(""));
        assert!(!own.contains("Access-Control-Allow-Origin"), "nothing but a realm asset to an opaque origin carries CORS");
    }
}

// TWO-PARTY-REVIEWED: the policy one node serves a Veil page under, read back from its own bytes. A site opened in the
// wallet's Browser against a real node is the real-node check `scratchpad/net/veil.py`.
#[cfg(test)]
mod veil_safe_tests {
    use super::*;

    #[test]
    fn a_veil_page_is_sandboxed_reaches_nothing_and_never_hands_over_a_program() {
        let page = veil_response("flame", "index.html", b"<!doctype html><html><head><title>x</title></head><body>hi</body></html>".to_vec());
        let wire = String::from_utf8_lossy(&page.to_bytes(false)).to_string();
        let csp = wire.lines().find(|l| l.starts_with("Content-Security-Policy:")).expect("a policy");
        assert!(csp.contains("sandbox allow-scripts allow-forms;"), "⛔ a Veil page shares the wallet apps' origin");
        assert!(!csp.contains("allow-same-origin") && !csp.contains("allow-top-navigation") && !csp.contains("allow-popups") && !csp.contains("allow-downloads"));
        assert!(csp.contains("connect-src 'none'"), "⛔ a Veil page can send what it learns somewhere");
        assert!(!csp.contains("'self'") && !csp.contains("27751"), "⛔ a Veil page may load another site's or an app's code, or reach the wallet's door");
        assert!(csp.contains("script-src http://127.0.0.1:27752/mud/flame/ "), "scripts come from the site's own path");
        for h in ["Permissions-Policy: camera=()", "microphone=()", "payment=()", "clipboard-read=()", "Referrer-Policy: no-referrer", "X-Content-Type-Options: nosniff"] {
            assert!(wire.contains(h), "missing {h}");
        }
        // a sandboxed page has an origin of its own: a header that keeps resources to the host's origin would refuse
        // the page its own pictures and scripts, and framing is the policy's frame-ancestors alone
        assert!(!wire.contains("Cross-Origin-Resource-Policy") && !wire.contains("X-Frame-Options"));
        // the wallet's scheme gets the same policy, for its own address
        let at = veil_csp_at(&["veil://localhost".to_string(), "http://veil.localhost".to_string()], "flame");
        assert!(at.contains("script-src veil://localhost/mud/flame/ http://veil.localhost/mud/flame/ 'unsafe-inline'") && at.contains("connect-src 'none'") && at.starts_with("sandbox allow-scripts allow-forms;"));
        // the wallet's own apps keep their policy
        let app = HttpResponse::text(200, "OK", "<p>app</p>").to_bytes(false);
        assert!(String::from_utf8_lossy(&app).contains("default-src 'self'") && !String::from_utf8_lossy(&app).contains("sandbox"));
        // the nav script sits first in the head, and a page with no head gets it at the start
        let body = String::from_utf8(page.body).expect("utf-8");
        assert!(body.starts_with("<!doctype html><html><head><script>") && body.contains("monerousd:veil-back"));
        assert!(String::from_utf8(with_nav(b"just text".to_vec())).expect("utf-8").starts_with("<script>"));
        // a program is shown as text, never delivered; a picture stays a picture and gets no script
        for f in ["setup.exe", "Install.dmg", "run.sh", "a/b/tool.command", "x.APK", "evil.scpt"] {
            let r = veil_response("flame", f, b"MZ\x90\x00".to_vec());
            assert_eq!(r.content_type, "text/plain; charset=utf-8", "{f} would be handed to the machine");
            assert_eq!(r.body, b"MZ\x90\x00", "{f}'s bytes changed");
        }
        let img = veil_response("flame", "img/cat.png", vec![0x89, b'P', b'N', b'G']);
        assert_eq!((img.content_type.as_str(), img.body.len()), ("image/png", 4));
    }
}

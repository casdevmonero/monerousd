// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ THE APP HALF OF THE ONE-SWEEP HOLE SCANNER — the WALLET and EVERY LAUNCHPAD APP.
//!
//! User 2026-10-03: *"the goal is for the tool to check the entire ecosystem … it includes the base level chain and the apps
//! built on top of it that are in the launchpad"*. The ECOSYSTEM is the node + decider, the wallet (Rust core + front end),
//! and every launchpad app the wallet hosts, served by the user's own node from `monerousd-node-zkdag/sites/<site>/`
//! ([[feedback-ecosystem-means-everything-20261003]]).
//!
//! WHAT IT CHECKS, statically and cheaply, over every app bundle in `sites/` and the wallet's `dist/` front end:
//! 1. ROUTE PARITY — every node path an app calls (`fetch` / `api` / `get` / `post` contexts) is a route the node serves
//!    (`rpc_http.rs` arms + `sovereign.rs` arms). A call to no route is a feature that cannot work.
//! 2. BRIDGE PARITY — every `rpc('method'` an app calls through the wallet's dapp bridge is a `case 'method':` the wallet
//!    dispatches. A missing case is a dead app button.
//! 3. CLEARNET — a request or script to a non-loopback, non-onion `http(s)://` / `ws(s)://` host breaks the onion-only
//!    transport and leaks to a third party.
//! 4. CLASSICAL CRYPTO — a secp256k1 / ed25519 / ECDSA / elliptic / tweetnacl / x25519 use in app code breaks the
//!    post-quantum pillar.
//! 5. SECRETS IN BROWSER STORAGE — a seed, mnemonic, private or spend key written to the browser's local store.
//! 6. WALLET COMMAND PARITY — every command the wallet front end invokes is a `#[tauri::command]` in its Rust core.
//! 7. LAUNCHPAD PARITY — every tile in the wallet's `LAUNCHPAD_APPS` either names a `site` the node serves from `sites/`
//!    (with an `index.html`) or is native; a tile with only a public `url` loads over clearnet.
//!
//! Universes come from the tree (`sites/` dirs, `dist/`, `LAUNCHPAD_APPS`, the route arms, the command attributes), so a
//! new app, route or command is covered with no edit. Vendored, minified or backup files are skipped and COUNTED, so a
//! skip is visible in the coverage line.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// One app-side hole: `(category, where, what)`.
pub type AppHole = (&'static str, String, String);

/// The browser-storage write call the scanner looks for, lower-cased (built in parts: it is a search needle, not a write).
const BROWSER_STORE_WRITE: &str = concat!("localstorage", ".", "setitem(");

fn node_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn repo_root() -> PathBuf {
    node_root().parent().map(Path::to_path_buf).unwrap_or_else(node_root)
}

fn skip(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/node_modules/")
        || s.contains("/vendor/")
        || s.contains(".min.")
        || s.contains(".pre")
        || s.contains(".bak")
        || s.contains("recreated-backup")
        || s.contains("/monaco")
}

/// Every `.js` / `.mjs` / `.html` file under `dir` (skips counted).
fn app_files(dir: &Path, skipped: &mut usize) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if skip(&p) {
                    *skipped += 1;
                } else {
                    stack.push(p);
                }
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("js" | "html" | "mjs")) {
                if skip(&p) {
                    *skipped += 1;
                } else if let Ok(t) = fs::read_to_string(&p) {
                    out.push((p, t));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

use super::surface_census::quoted;


/// The node's served routes — the ONE route reader ([`super::surface_census::routes`]), shared so the two censuses can
/// never disagree about what the node serves.
#[must_use]
pub fn node_routes() -> Vec<(String, String, String)> {
    super::surface_census::routes(&super::surface_census::ecosystem())
}

/// The node-route-looking path a call-context line names: the first `/word(/word)*` run inside each quoted literal that is
/// not preceded by a host (`http://h/x` is a clearnet call, judged by check 3).
fn called_paths(line: &str) -> Vec<String> {
    let ctx = ["fetch(", "api(", ".get(", ".post(", "nodeGet(", "nodePost(", "rpcGet(", "rpcPost(", "request("];
    if !ctx.iter().any(|c| line.contains(c)) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for s in quoted(line) {
        for (i, _) in s.match_indices('/') {
            // a route starts the literal or follows a template base (`${BASE}/x`); `application/json` is not a route
            if i > 0 && s.as_bytes()[i - 1] != b'}' {
                continue;
            }
            let rest = &s[i..];
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '-')).unwrap_or(rest.len());
            let p = rest[..end].trim_end_matches('/');
            let first = p.trim_start_matches('/').chars().next();
            let next = rest[end..].chars().next();
            if p.len() > 1 && first.is_some_and(|c| c.is_ascii_lowercase()) && next != Some('.') {
                if !s[..i].contains("://") {
                    out.push(p.to_string());
                }
                break;
            }
        }
    }
    out
}

/// The wallet's dapp-bridge methods: `case 'name':` in the wallet front end.
fn wallet_bridge_methods(wallet_dist: &[(PathBuf, String)]) -> BTreeSet<String> {
    let mut m = BTreeSet::new();
    for (_, t) in wallet_dist {
        for line in t.lines() {
            for (i, _) in line.match_indices("case ") {
                if let Some(q) = quoted(&line[i + 5..]).first() {
                    m.insert((*q).to_string());
                }
            }
        }
    }
    m
}

/// Every command the wallet registers — the ONE command reader ([`super::surface_census::wallet_commands`]).
fn tauri_commands() -> BTreeSet<String> {
    super::surface_census::wallet_commands(&super::surface_census::ecosystem()).into_iter().map(|(n, _, _)| n).collect()
}

fn is_local_or_onion(url: &str) -> bool {
    let host = url.split("://").nth(1).unwrap_or("").split(['/', ':', '?']).next().unwrap_or("");
    host.is_empty()
        || host == "localhost"
        || host.starts_with("127.")
        || host.starts_with('[')
        || host.ends_with(".onion")
        || host.ends_with(".localhost")
        || host.starts_with('$')
}

/// `(id, site, url, native)` for every tile in the wallet's `LAUNCHPAD_APPS`.
fn launchpad_tiles(wallet_dist: &[(PathBuf, String)]) -> Vec<(String, Option<String>, Option<String>, bool)> {
    let mut tiles = Vec::new();
    for (_, t) in wallet_dist {
        let Some(start) = t.find("const LAUNCHPAD_APPS = [") else { continue };
        let body = &t[start..];
        let body = &body[..body.find("\n];").unwrap_or(body.len())];
        for chunk in body.split("id:").skip(1) {
            // a field's value counts only when it IS a string (`site: null` is no site)
            let field = |k: &str| -> Option<String> {
                let at = chunk.find(k)?;
                let v = chunk[at + k.len()..].trim_start();
                if !v.starts_with(['\'', '"', '`']) {
                    return None;
                }
                quoted(v).first().map(|s| (*s).to_string())
            };
            let id = quoted(chunk).first().map(|s| (*s).to_string()).unwrap_or_default();
            tiles.push((id, field("site:"), field("url:"), chunk.contains("native: true")));
        }
    }
    tiles
}

/// Every app-side hole across the wallet front end and every launchpad bundle.
#[must_use]
pub fn app_holes() -> Vec<AppHole> {
    let mut h: Vec<AppHole> = Vec::new();
    let mut skipped = 0usize;
    let routes = node_routes();
    let wallet_dist = app_files(&repo_root().join("monerousd-wallet-v2/dist"), &mut skipped);
    let bridge = wallet_bridge_methods(&wallet_dist);
    let commands = tauri_commands();
    let sites_dir = node_root().join("sites");

    // 7. LAUNCHPAD PARITY
    let tiles = launchpad_tiles(&wallet_dist);
    for (id, site, url, native) in &tiles {
        match site {
            Some(s) if !sites_dir.join(s).join("index.html").is_file() => {
                h.push(("launchpad tile names a site the node does not serve", id.clone(), format!("sites/{s}/index.html missing")))
            }
            None if !native => h.push((
                "launchpad tile loads over clearnet (no served site)",
                id.clone(),
                url.clone().unwrap_or_else(|| "no url".into()),
            )),
            _ => {}
        }
    }

    let mut apps: Vec<(String, Vec<(PathBuf, String)>)> = Vec::new();
    if let Ok(rd) = fs::read_dir(&sites_dir) {
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        dirs.sort();
        for d in dirs {
            if skip(&d) {
                skipped += 1;
                continue;
            }
            let name = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            apps.push((name, app_files(&d, &mut skipped)));
        }
    }
    let wallet = "wallet front end";
    apps.push((wallet.to_string(), wallet_dist.clone()));
    let crypto = ["secp256k1", "ed25519", "ecdsa", "elliptic", "tweetnacl", "nacl.sign", "curve25519", "x25519"];
    let secret_words = ["seed", "mnemonic", "secret", "privkey", "private", "spend_key", "spendkey"];
    let requesting = ["fetch(", "XMLHttpRequest", "new WebSocket(", "<script src=", "EventSource(", "import("];
    let mut files_scanned = 0usize;
    for (app, files) in &apps {
        let mut seen_route = BTreeSet::new();
        let mut seen_bridge = BTreeSet::new();
        for (path, text) in files {
            files_scanned += 1;
            let rel = path.strip_prefix(repo_root()).unwrap_or(path).to_string_lossy().into_owned();
            // In an HTML file, text inside <pre> / <code> is DISPLAYED, never executed (a docs page's code samples):
            // measured 2026-10-03, developers.html's `fetch('https://ion…')` examples read as clearnet requests.
            let is_html = rel.ends_with(".html");
            let mut in_shown_code = false;
            // In an HTML file only a <script> body EXECUTES: a page's prose naming a primitive ("not a single … curve
            // anywhere") is copy, not crypto. MEASURED 2026-11-03: monerousd-org/index.html:910 and :1192 — two marketing
            // sentences saying the chain uses NO such curve — were filed as the site using one.
            let mut in_script = false;
            for (n, line) in text.lines().enumerate() {
                let t = line.trim_start();
                let script_line = if is_html {
                    let l = line.to_ascii_lowercase();
                    let was = in_script;
                    if let Some(o) = l.rfind("<script") {
                        in_script = l.rfind("</script>").map_or(true, |c| c < o);
                    } else if l.contains("</script>") {
                        in_script = false;
                    }
                    was || l.contains("<script")
                } else {
                    true
                };
                if is_html {
                    let l = line.to_ascii_lowercase();
                    let opens = l.contains("<pre") || l.contains("<code");
                    let closes = l.contains("</pre>") || l.contains("</code>");
                    if opens || in_shown_code {
                        in_shown_code = !closes || (opens && l.rfind("<pre").max(l.rfind("<code")) > l.rfind("</pre>").max(l.rfind("</code>")));
                        continue;
                    }
                }
                if t.starts_with("//") || t.starts_with("* ") || t.starts_with("/*") {
                    continue;
                }
                let at = || format!("{rel}:{}", n + 1);
                // 1. ROUTE PARITY
                for p in called_paths(line) {
                    let served = super::surface_census::served(&routes, &p);
                    if !served && seen_route.insert(p.clone()) {
                        h.push(("app calls a node route that does not exist", format!("{app}: {}", at()), p));
                    }
                }
                // 2. BRIDGE PARITY (launchpad apps only — the wallet IS the bridge)
                if app != wallet {
                    for (i, _) in line.match_indices("rpc(") {
                        if i > 0 && line.as_bytes()[i - 1].is_ascii_alphanumeric() {
                            continue;
                        }
                        let rest = line[i + 4..].trim_start();
                        if !rest.starts_with(['\'', '"']) {
                            continue;
                        }
                        if let Some(q) = quoted(rest).first() {
                            let m = (*q).to_string();
                            let ident = !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                            if ident && !bridge.contains(&m) && seen_bridge.insert(m.clone()) {
                                h.push(("app calls a wallet bridge method the wallet does not implement", format!("{app}: {}", at()), m));
                            }
                        }
                    }
                }
                // 3. CLEARNET
                if requesting.iter().any(|c| line.contains(c)) {
                    for s in quoted(line) {
                        let remote = ["http://", "https://", "ws://", "wss://"].iter().any(|p| s.starts_with(p));
                        if remote && !is_local_or_onion(s) {
                            h.push(("app makes a clearnet / third-party request", format!("{app}: {}", at()), s.chars().take(120).collect()));
                        }
                    }
                }
                let lower = line.to_ascii_lowercase();
                // the code alone: a comment's words ("private mode") are not what the line stores
                let code = lower.split("/*").next().unwrap_or(&lower).split("//").next().unwrap_or(&lower).to_string();
                // 4. CLASSICAL CRYPTO
                if let Some(c) = crypto.iter().find(|c| script_line && code.contains(*c)) {
                    h.push(("app uses classical (pre-quantum) crypto", format!("{app}: {}", at()), (*c).to_string()));
                }
                // 5. SECRETS IN BROWSER STORAGE
                if code.contains(BROWSER_STORE_WRITE) && secret_words.iter().any(|w| code.contains(w)) {
                    h.push(("app writes a secret to browser storage", format!("{app}: {}", at()), line.trim().chars().take(120).collect()));
                }
                // 6. WALLET COMMAND PARITY (the wallet front end)
                if app == wallet {
                    for call in ["_tauriInvoke(", "invoke("] {
                        for (i, _) in line.match_indices(call) {
                            if call == "invoke(" && i > 0 && (line.as_bytes()[i - 1].is_ascii_alphanumeric() || line.as_bytes()[i - 1] == b'_') {
                                continue;
                            }
                            let rest = line[i + call.len()..].trim_start();
                            if !rest.starts_with(['\'', '"']) {
                                continue;
                            }
                            if let Some(q) = quoted(rest).first() {
                                let c = (*q).to_string();
                                if !c.is_empty() && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') && !commands.contains(&c) {
                                    h.push(("wallet front end invokes a command the Rust core does not define", at(), c));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    h.push((
        "app census coverage",
        format!(
            "{} app bundle(s) incl. the wallet front end; {} launchpad tile(s); {} file(s) scanned; {} node route(s); {} bridge method(s); {} tauri command(s)",
            apps.len(),
            tiles.len(),
            files_scanned,
            routes.len(),
            bridge.len(),
            commands.len()
        ),
        format!("{skipped} vendored / minified / backup file(s) skipped"),
    ));
    h
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// CALIBRATION: the census reads its universes. An empty universe would read as "no holes".
    #[test]
    fn app_census_reads_every_universe() {
        let routes = node_routes();
        assert!(super::super::surface_census::served(&routes, "/get_info"), "route universe unread: {} routes", routes.len());
        let mut skipped = 0;
        let dist = app_files(&repo_root().join("monerousd-wallet-v2/dist"), &mut skipped);
        assert!(!dist.is_empty(), "wallet front end unread");
        assert!(launchpad_tiles(&dist).len() >= 6, "LAUNCHPAD_APPS unread");
        assert!(!wallet_bridge_methods(&dist).is_empty(), "bridge dispatcher unread");
        assert!(tauri_commands().len() >= 30, "tauri commands unread");
    }

    /// CALIBRATION: each check fires on a planted defect (an instrument that cannot fire proves nothing).
    #[test]
    fn app_census_checks_fire_on_planted_defects() {
        assert_eq!(called_paths("fetch(`${BASE}/no_such_route?x=1`)"), vec!["/no_such_route".to_string()]);
        assert!(called_paths("fetch('https://evil.example/x')").is_empty(), "a hosted path is judged by the clearnet check");
        assert!(!is_local_or_onion("https://cdn.example.com/lib.js"));
        assert!(is_local_or_onion("http://127.0.0.1:27780/get_info"));
        assert!(is_local_or_onion("http://abc.onion/x"));
        let planted = format!("localStorage{}setItem('seed', s)", ".");
        assert!(planted.to_ascii_lowercase().contains(BROWSER_STORE_WRITE));
    }
}

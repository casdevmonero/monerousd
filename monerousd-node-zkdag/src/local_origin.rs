// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ DB-374 — THE NODE'S LOCAL HTTP SERVERS ANSWER ONLY THE USER'S OWN SOFTWARE, NOT ANY WEB PAGE THEY VISIT.
//!
//! MEASURED 2026-10-03 by the hole scanner (`harness::surface_census`, "local HTTP server answers any web page"):
//! `rpc_http` (:27780) and the sovereign site server (:27752) checked neither `Host` nor `Origin` and answered every
//! response with `Access-Control-Allow-Origin: *`.
//! - Loopback binding keeps the NETWORK out, not the user's own browser. Any site the user visits can POST to
//!   `127.0.0.1:27780` (CSRF), and with `*` it can READ every answer.
//! - Through DNS rebinding (a hostile name re-pointed at 127.0.0.1) it reads them even under a strict policy.
//!
//! THE BORROWED SHAPE (geth `--http.vhosts` + `--http.corsdomain`, defaults `localhost`):
//! 1. `Host` must name the loopback interface. A rebinding page's requests carry the ATTACKER's host name, so this one
//!    check defeats DNS rebinding whatever the browser does.
//! 2. `Origin`, when a browser sends one, must be the user's own software: a loopback origin (the node's own sovereign
//!    apps) or the wallet's Tauri webview. A request with no `Origin` is a non-browser local client (the wallet core,
//!    curl, the harness) and is admitted.
//! 3. `Sec-Fetch-Site: cross-site` with no admitted `Origin` (a no-cors navigation, `<img src>`, a form post) is refused.
//! 4. The CORS answer echoes the ADMITTED origin, never `*`.
//!
//! §9.6 door answers (this is an admission check on two existing doors, not a new door):
//! - **Proof of work / proof / conservation / replay:** unchanged; every route keeps its own checks.
//! - **Bounded work:** a refused request is answered 403 before any route runs.
//! - **Parity:** both local servers run the ONE function, [`admit`].

/// What a request says about where it came from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestOrigin {
    pub host: Option<String>,
    pub origin: Option<String>,
    pub fetch_site: Option<String>,
}

impl RequestOrigin {
    /// Read the three headers from a request head (`Name: value` lines; names case-insensitive).
    #[must_use]
    pub fn from_head(head: &str) -> Self {
        let mut o = Self::default();
        for line in head.split("\r\n").skip(1) {
            let Some((name, value)) = line.split_once(':') else { continue };
            let value = value.trim().to_string();
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => o.host = Some(value),
                "origin" => o.origin = Some(value),
                "sec-fetch-site" => o.fetch_site = Some(value.to_ascii_lowercase()),
                _ => {}
            }
        }
        o
    }
}

/// A host[:port] that names the loopback interface.
fn loopback_host(hostport: &str) -> bool {
    let h = hostport.trim().to_ascii_lowercase();
    if let Some(rest) = h.strip_prefix('[') {
        // [::1] or [::1]:port
        return matches!(rest.split_once(']'), Some(("::1", _)));
    }
    let name = match h.split_once(':') {
        Some((n, _)) => n,
        None => h.as_str(),
    };
    name == "localhost" || name == "127.0.0.1" || name.ends_with(".localhost")
}

/// The user's own software: a loopback web origin (the node's sovereign apps) or the wallet's Tauri webview.
fn own_origin(origin: &str) -> bool {
    let o = origin.trim().to_ascii_lowercase();
    if o == "tauri://localhost" || o == "http://tauri.localhost" || o == "https://tauri.localhost" {
        return true;
    }
    match o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")) {
        Some(hostport) => !hostport.contains('/') && loopback_host(hostport),
        None => false,
    }
}

/// Admit or refuse a request to a local server. `Ok(Some(origin))` = admitted, echo that origin in CORS;
/// `Ok(None)` = admitted, no CORS header (a non-browser client); `Err(why)` = refuse with 403.
///
/// `cross_site_reads_ok`: the sovereign server's GET/HEAD of a PUBLIC site is embedded cross-site by the wallet
/// (`tauri://localhost` frames `http://127.0.0.1:27752`, a navigation that carries no `Origin`), and a site's public
/// bytes reveal nothing — so those reads skip rule 3. The RPC passes `false`: every RPC answer is the node's.
pub fn admit(o: &RequestOrigin, cross_site_reads_ok: bool) -> Result<Option<String>, &'static str> {
    if let Some(h) = &o.host {
        if !loopback_host(h) {
            return Err("host is not this machine's loopback name (DNS rebinding)");
        }
    }
    match &o.origin {
        Some(origin) if own_origin(origin) => Ok(Some(origin.clone())),
        Some(_) => Err("origin is not the user's own wallet or node app"),
        None => match o.fetch_site.as_deref() {
            Some("cross-site") if !cross_site_reads_ok => Err("a cross-site request with no origin"),
            _ => Ok(None),
        },
    }
}

/// The CORS header lines for an admitted request (empty for a non-browser client).
#[must_use]
pub fn cors_headers(admitted: Option<&str>) -> String {
    match admitted {
        Some(origin) => format!(
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: content-type\r\n"
        ),
        None => String::new(),
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn req(host: Option<&str>, origin: Option<&str>, site: Option<&str>) -> RequestOrigin {
        RequestOrigin { host: host.map(String::from), origin: origin.map(String::from), fetch_site: site.map(String::from) }
    }
    /// The RPC's admission (strict on every request).
    fn rpc(o: &RequestOrigin) -> Result<Option<String>, &'static str> {
        admit(o, false)
    }

    /// DB-374 — the sovereign server: the wallet's cross-site FRAMING of a public site is admitted; a rebinding page's
    /// read of the same site, or any foreign WRITE, is refused.
    #[test]
    fn db374_the_sovereign_server_admits_the_wallets_framing_and_refuses_the_rest() {
        assert_eq!(admit(&req(Some("127.0.0.1:27752"), None, Some("cross-site")), true), Ok(None), "tauri frames a site");
        assert!(admit(&req(Some("evil.example:27752"), None, Some("cross-site")), true).is_err(), "rebinding read");
        assert!(admit(&req(Some("127.0.0.1:27752"), None, Some("cross-site")), false).is_err(), "a foreign write");
        assert!(admit(&req(Some("127.0.0.1:27752"), Some("https://evil.example"), None), true).is_err());
    }

    /// DB-374 adversarial pin: every way a web page the user visits reaches the node is REFUSED.
    #[test]
    fn db374_a_visited_web_page_cannot_reach_the_local_node() {
        // DNS rebinding: the page's own host name, re-pointed at 127.0.0.1
        assert!(rpc(&req(Some("evil.example:27780"), None, None)).is_err());
        assert!(rpc(&req(Some("127.0.0.1.evil.example"), Some("http://127.0.0.1.evil.example"), None)).is_err());
        // CSRF / read from a foreign origin
        assert!(rpc(&req(Some("127.0.0.1:27780"), Some("https://evil.example"), Some("cross-site"))).is_err());
        assert!(rpc(&req(Some("127.0.0.1:27780"), Some("null"), None)).is_err(), "a sandboxed frame's null origin");
        assert!(rpc(&req(Some("127.0.0.1:27780"), Some("http://127.0.0.1.nip.io"), None)).is_err());
        // a no-cors navigation / <img src> / form post from another site carries no Origin but says cross-site
        assert!(rpc(&req(Some("127.0.0.1:27780"), None, Some("cross-site"))).is_err());
    }

    /// DB-374: the user's own software is admitted, and CORS echoes it (never `*`).
    #[test]
    fn db374_the_wallet_and_the_nodes_own_apps_are_admitted() {
        assert_eq!(rpc(&req(Some("127.0.0.1:27780"), None, None)), Ok(None), "the wallet core / curl / the harness");
        assert_eq!(rpc(&req(None, None, None)), Ok(None));
        for own in ["tauri://localhost", "http://tauri.localhost", "http://127.0.0.1:27752", "http://localhost:27752", "http://[::1]:27752"] {
            assert_eq!(rpc(&req(Some("127.0.0.1:27780"), Some(own), Some("same-site"))), Ok(Some(own.to_string())), "{own}");
        }
        assert!(cors_headers(Some("tauri://localhost")).contains("Access-Control-Allow-Origin: tauri://localhost"));
        assert!(!cors_headers(Some("tauri://localhost")).contains('*'));
        assert!(cors_headers(None).is_empty());
    }

    /// DB-374 across a real socket: a CLIENT sends a browser's exact hostile request bytes to a SERVER that reads the
    /// head and runs [`admit`]; the client OBSERVES the refusal. The two parties of this attack are, by definition, a
    /// web page and the local server on ONE machine — the boundary crossed is HTTP over the loopback interface.
    /// TWO-PARTY-REVIEWED: two endpoints (a listener thread as the server, the test thread as the browser) on two
    /// sockets; the server never sees the client's intent except through the wire bytes, and the assertion is what the
    /// CLIENT reads back.
    #[test]
    fn db374_a_hostile_request_crossing_the_socket_is_answered_403() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).expect("read");
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let code = match admit(&RequestOrigin::from_head(&head), false) {
                    Ok(_) => 200,
                    Err(_) => 403,
                };
                let _ = s.write(format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
            }
        });
        let ask = |raw: &str| -> String {
            let mut c = std::net::TcpStream::connect(addr).expect("connect");
            c.write(raw.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = c.read_to_string(&mut out);
            out
        };
        let hostile = ask("POST /submit_pq_tx HTTP/1.1\r\nHost: 127.0.0.1:27780\r\nOrigin: https://evil.example\r\n\
                           Sec-Fetch-Site: cross-site\r\nContent-Length: 0\r\n\r\n");
        assert!(hostile.starts_with("HTTP/1.1 403"), "a foreign page's POST must be refused: {hostile}");
        let own = ask("GET /get_info HTTP/1.1\r\nHost: 127.0.0.1:27780\r\nOrigin: tauri://localhost\r\n\r\n");
        assert!(own.starts_with("HTTP/1.1 200"), "the wallet's own webview must be admitted: {own}");
        server.join().expect("server");
    }
}

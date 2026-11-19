// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! EMBEDDED RUST TOR (arti) — onion transport for the wallet WITHOUT a bundled `tor` subprocess.
//!
//! WHY: on desktop the wallet reaches the chain through its LOCAL node (a subprocess that runs Tor). iOS forbids
//! spawning subprocesses, so the iPhone build reaches the pinned MonerousD seed node's Tor v3 `.onion` RPC
//! itself. This module bootstraps ONE in-process arti `TorClient` and runs a LOOPBACK FORWARDER on
//! `127.0.0.1:<local_port>` that tunnels every connection to `<onion>:<remote_port>` through Tor. Because the
//! forwarder listens on the SAME loopback port the wallet already targets (`127.0.0.1:27780`), the whole HTTP
//! layer is unchanged — every existing request transparently rides Tor to the onion RPC, zero call-site edits.
//!
//! ONION-ONLY BY CONSTRUCTION (Pillar 1): the ONLY egress this module performs is a Tor circuit to the exact
//! `.onion` host it is given — never clearnet, never a raw IP. If arti is not yet bootstrapped the forwarder
//! does not start and the wallet stays FAIL-CLOSED (an honest "connecting…" state in the UI). arti is pure Rust
//! (no C tor), cross-compiles to `aarch64-apple-ios`, and is 100% parity with the desktop's onion transport; it
//! also gives DESKTOP a node-unreachable onion path (availability pillar). Bootstrapped once and cached.

use arti_client::{TorClient, TorClientConfig};
use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use tokio::sync::watch;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;

/// The tokio runtime that owns arti for the app's lifetime, plus a WATCH channel that publishes the
/// bootstrapped client the instant it is ready. We never block a caller on bootstrap: the runtime is built
/// synchronously (a cheap, no-network operation) and `create_bootstrapped` runs as a background TASK on it,
/// sending the `Arc<TorClient>` through the watch when done. Per-connection handlers `await` the watch, so the
/// loopback listener comes up IMMEDIATELY and circuits attach asynchronously — parity with the node's instant
/// Tor bring-up (no startup blocks up to a minute on consensus fetch).
struct Tor {
    rt: tokio::runtime::Runtime,
    // `None` until arti finishes bootstrapping; then `Some(Arc<TorClient>)`. Handlers clone this receiver and
    // wait for the first `Some`, then take a fresh `isolated_client()` per connection (unlinkable circuits).
    client_rx: watch::Receiver<Option<Arc<TorClient<PreferredRuntime>>>>,
}

static TOR: OnceLock<Option<Tor>> = OnceLock::new();
/// Guards the single loopback forwarder so `ensure_onion_rpc` is idempotent (start once, reuse thereafter).
static FORWARDER: OnceLock<bool> = OnceLock::new();

/// Get the shared Tor handle, building the runtime + kicking off a BACKGROUND bootstrap on first call. This
/// returns immediately (no `block_on`); the client publishes through the watch when its consensus + first
/// circuit are ready. `None` only if the tokio runtime itself cannot be built. Callers stay fail-closed until a
/// circuit exists (the loopback tunnel simply holds the connection until then; never any non-Tor egress).
fn tor() -> Option<&'static Tor> {
    TOR.get_or_init(build_tor).as_ref()
}

fn build_tor() -> Option<Tor> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("usdm-tor")
        .build()
        .ok()?;
    // Publish the client the moment it is ready — DO NOT block the caller on the bootstrap.
    let (tx, client_rx) = watch::channel::<Option<Arc<TorClient<PreferredRuntime>>>>(None);
    rt.spawn(async move {
        match TorClient::builder()
            .config(TorClientConfig::default())
            .create_bootstrapped()
            .await
        {
            Ok(client) => {
                eprintln!("[tor] arti bootstrapped (async — startup did NOT block on this)");
                let _ = tx.send(Some(client));
            }
            Err(e) => eprintln!("[tor] arti bootstrap failed: {e}"),
        }
    });
    Some(Tor { rt, client_rx })
}

/// Ensure a loopback forwarder is running that tunnels `127.0.0.1:<local_port>` → `<onion>:<remote_port>` over
/// Tor. Idempotent + cached, and NON-BLOCKING: it returns as soon as the loopback listener is up (typically
/// sub-millisecond — binding a local socket needs no network), while arti bootstraps on a background task. The
/// wallet's HTTP client keeps talking to `127.0.0.1:<local_port>` exactly as on desktop; each connection is
/// held until the first Tor circuit is ready, then carried to the hidden service.
pub fn ensure_onion_rpc(onion: &str, remote_port: u16, local_port: u16) -> bool {
    let onion = onion.to_string();
    *FORWARDER.get_or_init(|| start_forwarder(onion, remote_port, local_port))
}

fn start_forwarder(onion: String, remote_port: u16, local_port: u16) -> bool {
    // ONION-ONLY: refuse to forward to anything that is not a Tor v3 hidden service (Pillar 1, enforced here so
    // no misconfiguration can ever open a non-Tor path).
    if !onion.ends_with(".onion") {
        eprintln!("[tor] refusing non-onion target (onion-only)");
        return false;
    }
    let tor = match tor() {
        Some(t) => t,
        None => return false,
    };
    let client_rx = tor.client_rx.clone();
    // Bind the loopback listener + run the accept loop entirely inside a background task, so `ensure_onion_rpc`
    // returns instantly (no `block_on` on the caller). The listener is a local socket — it comes up right away,
    // so the wallet's `connect 127.0.0.1:<local_port>` succeeds immediately; the request then waits inside the
    // tunnel only until arti's first circuit is ready (the honest "connecting…" window, which the UI polls).
    tor.rt.spawn(async move {
        let listener = match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, local_port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[tor] forwarder bind 127.0.0.1:{local_port} failed: {e}");
                return;
            }
        };
        eprintln!("[tor] onion RPC forwarder listening: 127.0.0.1:{local_port} -> {onion}:{remote_port} (circuits attach async)");
        carry_to_onion(listener, onion, remote_port, client_rx).await;
    });
    true
}

/// THE ONE ACCEPT LOOP of every loopback forwarder: each local connection waits for arti, then rides its own fresh
/// circuit to `<onion>:<remote_port>`. Nothing else leaves this module.
async fn carry_to_onion(
    listener: tokio::net::TcpListener,
    onion: String,
    remote_port: u16,
    client_rx: watch::Receiver<Option<Arc<TorClient<PreferredRuntime>>>>,
) {
    loop {
        match listener.accept().await {
            Ok((mut inbound, _)) => {
                let mut rx = client_rx.clone();
                let onion = onion.clone();
                tokio::spawn(async move {
                    // Wait (without blocking any OS thread) for arti to finish bootstrapping, then dial.
                    let client = loop {
                        if let Some(c) = rx.borrow_and_update().clone() {
                            break c;
                        }
                        if rx.changed().await.is_err() {
                            return; // sender dropped — app shutting down
                        }
                    };
                    let client = client.isolated_client(); // fresh circuit per connection (unlinkable)
                    match client.connect((onion.as_str(), remote_port)).await {
                        Ok(stream) => {
                            let mut outbound = stream.compat();
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                        Err(e) => eprintln!("[tor] dial {onion}:{remote_port} failed: {e}"),
                    }
                });
            }
            Err(_) => break,
        }
    }
}

/// Is `host` a Tor v3 hidden-service name (56 base32 characters and `.onion`)? The only kind of remote host this wallet
/// ever opens a connection to.
pub fn is_onion_v3(host: &str) -> bool {
    match host.strip_suffix(".onion") {
        Some(name) => name.len() == 56 && name.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
        None => false,
    }
}

/// The forwarders this session opened to hidden services other than its node's (a shop's checkout), by target.
/// O1-FOOTPRINT-REVIEWED: RAM only, one small entry per shop this session paid; gone when the app closes.
static FORWARDS: OnceLock<std::sync::Mutex<std::collections::HashMap<(String, u16), u16>>> = OnceLock::new();

/// ⭐ goods spec §8 — A LOOPBACK DOOR TO ONE MORE HIDDEN SERVICE (a shop's checkout helper). Returns the local port whose
/// connections ride Tor to `<onion>:<remote_port>`; the same target always answers with the same port. `None` for a host
/// that is not a v3 hidden service (onion-only, enforced here) or when the runtime cannot start. The OS picks the port.
pub fn onion_forward(onion: &str, remote_port: u16) -> Option<u16> {
    if !is_onion_v3(onion) {
        eprintln!("[tor] refusing non-onion target (onion-only)");
        return None;
    }
    let mut open = FORWARDS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if let Some(port) = open.get(&(onion.to_string(), remote_port)) {
        return Some(*port);
    }
    let tor = tor()?;
    let bound = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    bound.set_nonblocking(true).ok()?;
    let port = bound.local_addr().ok()?.port();
    let client_rx = tor.client_rx.clone();
    let target = onion.to_string();
    tor.rt.spawn(async move {
        match tokio::net::TcpListener::from_std(bound) {
            Ok(listener) => carry_to_onion(listener, target, remote_port, client_rx).await,
            Err(e) => eprintln!("[tor] forwarder on 127.0.0.1:{port} failed: {e}"),
        }
    });
    open.insert((onion.to_string(), remote_port), port);
    Some(port)
}

/// ⭐ THE ONE CLEARNET EGRESS: A WALLET RELEASE, OVER TOR (lane speed5, 2026-11-18; user: "lets build the one click ota update
/// for the wallet now"). An HTTPS GET to one of `RELEASE_HOSTS` (GitHub's release download and the hosts it redirects to)
/// through an arti EXIT circuit, never a direct connection: GitHub sees a Tor exit, never this device's address, and the
/// request carries nothing about the user (a fixed User-Agent, no cookie). Every other egress of this module stays the
/// onion-only forwarder above. Redirects are followed only between `RELEASE_HOSTS`, at most `MAX_REDIRECTS`.
/// PQ: the TLS here is GitHub's classical crypto on its own data (the 2026-11-09 exception); a release is trusted only by
/// its ML-DSA-65 signature and the blake3 of each file (`updater.rs`), never by TLS.
/// Bounded: at most `max_bytes` of body, `timeout_s` in all. Blocking: call it off the UI thread.
pub fn https_get(url: &str, max_bytes: usize, timeout_s: u64) -> Result<Vec<u8>, String> {
    const RELEASE_HOSTS: [&str; 4] =
        ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "codeload.github.com"];
    const MAX_REDIRECTS: usize = 6;
    let t = tor().ok_or("Tor could not start on this device")?;
    let mut rx = t.client_rx.clone();
    let mut url = url.to_string();
    t.rt.block_on(async move {
        let deadline = std::time::Duration::from_secs(timeout_s);
        tokio::time::timeout(deadline, async move {
            let client = loop {
                if let Some(c) = rx.borrow().clone() {
                    break c;
                }
                rx.changed().await.map_err(|_| "Tor stopped before it connected".to_string())?;
            };
            for _ in 0..=MAX_REDIRECTS {
                let rest = url.strip_prefix("https://").ok_or("a release URL must be https")?;
                let (host, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
                if !RELEASE_HOSTS.contains(&host) {
                    return Err(format!("refused: {host} is not a release host"));
                }
                let stream = client.isolated_client().connect((host, 443)).await.map_err(|e| format!("Tor could not reach {host}: {e}"))?;
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| format!("TLS: {e}"))?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("TLS name: {e}"))?;
                let mut tls = futures_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
                    .connect(name, stream)
                    .await
                    .map_err(|e| format!("TLS to {host}: {e}"))?;
                use futures::io::{AsyncReadExt, AsyncWriteExt};
                let req = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: monerousd-wallet\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                );
                tls.write_all(req.as_bytes()).await.map_err(|e| format!("send: {e}"))?;
                tls.flush().await.map_err(|e| format!("send: {e}"))?;
                let mut raw = Vec::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match tls.read(&mut buf).await {
                        Ok(n) => n,
                        // a server that closes without TLS close_notify ends the body; what was read stands, and the
                        // caller's size and hash check decide whether it is whole
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                        Err(e) => return Err(format!("read: {e}")),
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if raw.len() > max_bytes + 64 * 1024 {
                        return Err(format!("refused: the answer is larger than {max_bytes} bytes"));
                    }
                }
                let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("a malformed HTTP answer")?;
                let head = String::from_utf8_lossy(&raw[..split]).to_string();
                let body = raw[split + 4..].to_vec();
                let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or("no HTTP status")?;
                let header = |k: &str| {
                    head.lines().skip(1).find_map(|l| {
                        let (a, b) = l.split_once(':')?;
                        a.trim().eq_ignore_ascii_case(k).then(|| b.trim().to_string())
                    })
                };
                if matches!(status, 301 | 302 | 303 | 307 | 308) {
                    url = header("location").ok_or("a redirect with no Location")?;
                    continue;
                }
                if status != 200 {
                    return Err(format!("{host} answered HTTP {status}"));
                }
                let body = if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
                    dechunk(&body)?
                } else {
                    body
                };
                if body.len() > max_bytes {
                    return Err(format!("refused: the answer is larger than {max_bytes} bytes"));
                }
                return Ok(body);
            }
            Err("too many redirects".to_string())
        })
        .await
        .map_err(|_| format!("no answer within {timeout_s} s"))?
    })
}

/// An HTTP/1.1 chunked body, decoded (sizes in hex, each chunk followed by CRLF, ended by a zero chunk).
fn dechunk(mut b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").ok_or("a malformed chunk")?;
        let size_text = String::from_utf8_lossy(&b[..eol]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "a malformed chunk size")?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 {
            return Err("a truncated chunk".to_string());
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod onion_name_tests {
    #[test]
    fn only_a_v3_hidden_service_name_is_a_host_this_wallet_dials() {
        let good = format!("{}.onion", "a".repeat(56));
        assert!(super::is_onion_v3(&good));
        for bad in ["example.com", "127.0.0.1", "short.onion", &format!("{}.onion", "A".repeat(56)), &format!("{}.onion.example.com", "a".repeat(56)), &format!("{}1.onion", "a".repeat(55))] {
            assert!(!super::is_onion_v3(bad), "{bad} was taken for a hidden service");
            assert!(super::onion_forward(bad, 80).is_none(), "a forwarder opened to {bad}");
        }
    }
}

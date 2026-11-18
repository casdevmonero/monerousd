// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! MoneroUSD live-mesh TX FLOOD (#14) — pumps REAL PQ spend carriers into a live node's mempool and measures
//! the true sustained ADMISSION rate (the live-TPS ceiling: every /submit_pq_tx runs the per-tx WHIR verify).
//!
//! Reads carriers produced by the `carrier_gen` pqpool bin (one hex-per-line), grinds each carrier's #72
//! anti-spam stamp with blake3 to the node's currently-required bits (queried from /get_info), and POSTs each
//! into the node over raw HTTP/1.1 (loopback — the user's OWN node; MonerousD is onion-only for node↔node, but
//! the loopback RPC is the local submit path). Prints OK/REJECTED tallies + admitted-TPS. Every carrier is a
//! real ZK proof; the node really verifies each one — nothing is simulated.
//!
//! Usage: tx_flood [CARRIER_FILE=/tmp/usdmd_carriers.hex] [HOST=127.0.0.1] [PORT=27780] [THREADS=cores]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let hx = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < b.len() {
        out.push((hx(b[i])? << 4) | hx(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Count leading zero BITS of a 32-byte digest (mirror of `mempool::leading_zero_bits` — the #72 stamp metric).
fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for &byte in h.iter() {
        if byte == 0 {
            n += 8;
        } else {
            n += byte.leading_zeros();
            break;
        }
    }
    n
}

/// Grind a #72 stamp: find a nonce so `leading_zero_bits(blake3(id || nonce_le)) >= need`. `id = blake3(blob)`
/// (the node's `PqTx::content_id`). Returns the winning nonce.
fn grind_stamp(id: &[u8; 32], need: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(id);
        buf.extend_from_slice(&nonce.to_le_bytes());
        let h = blake3::hash(&buf);
        if leading_zero_bits(h.as_bytes()) >= need {
            return nonce;
        }
        nonce += 1;
    }
}

/// One raw HTTP/1.1 request to the loopback node; returns (status_line_ok, body).
fn http(host: &str, port: u16, method: &str, path: &str, body: Option<&str>) -> Option<String> {
    let mut stream = TcpStream::connect((host, port)).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok()?;
    // Split headers from body at the blank line.
    resp.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

fn json_u64(body: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let i = body.find(&pat)? + pat.len();
    let rest = &body[i..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let carrier_file = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/tmp/usdmd_carriers.hex".to_string());
    let host = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(27780);
    let threads: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    let carriers: Vec<Vec<u8>> = std::fs::read_to_string(&carrier_file)
        .unwrap_or_else(|e| panic!("read carrier file {carrier_file}: {e}"))
        .lines()
        .filter_map(hex_decode)
        .collect();
    if carriers.is_empty() {
        eprintln!("[tx_flood] no carriers in {carrier_file}");
        return;
    }

    // Ask the node the currently-required stamp bits (scales with pool occupancy). Grind to need+MARGIN so a
    // transient occupancy rise (the #72 adaptive band) during the flood doesn't reject an in-flight carrier.
    let base_need = http(&host, port, "GET", "/get_info", None)
        .and_then(|b| json_u64(&b, "required_stamp_bits"))
        .unwrap_or(8) as u32;
    let margin: u32 = std::env::var("STAMP_MARGIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let need = base_need + margin;

    // PHASE 1 (UNTIMED): pre-grind every carrier's #72 stamp in parallel, so the timed phase measures ONLY the
    // node's admission throughput (the per-tx WHIR verify), not the client's blake3 grind.
    eprintln!(
        "[tx_flood] pre-grinding {} stamps to {} bits ({} threads)…",
        carriers.len(),
        need,
        threads
    );
    let carriers = Arc::new(carriers);
    let ground: Arc<Vec<Mutex<Option<(usize, String, u64)>>>> =
        Arc::new((0..carriers.len()).map(|_| Mutex::new(None)).collect());
    let gnext = Arc::new(AtomicU64::new(0));
    let gr = Instant::now();
    let mut gh = Vec::new();
    for _ in 0..threads {
        let (carriers, ground, gnext) = (
            Arc::clone(&carriers),
            Arc::clone(&ground),
            Arc::clone(&gnext),
        );
        gh.push(std::thread::spawn(move || loop {
            let i = gnext.fetch_add(1, Ordering::Relaxed) as usize;
            if i >= carriers.len() {
                break;
            }
            let blob = &carriers[i];
            let id = *blake3::hash(blob).as_bytes();
            let nonce = grind_stamp(&id, need);
            let hex: String = blob.iter().map(|b| format!("{:02x}", b)).collect();
            *ground[i].lock().unwrap() = Some((i, hex, nonce));
        }));
    }
    for h in gh {
        h.join().ok();
    }
    eprintln!(
        "[tx_flood] ground in {:.2}s. FLOODING {} carriers → {}:{} ({} threads)…",
        gr.elapsed().as_secs_f64(),
        carriers.len(),
        host,
        port,
        threads
    );

    // PHASE 2 (TIMED): POST every pre-ground carrier as fast as the node admits it.
    let ok = Arc::new(AtomicUsize::new(0));
    let rej = Arc::new(AtomicUsize::new(0));
    let err = Arc::new(AtomicUsize::new(0));
    let next = Arc::new(AtomicU64::new(0));
    let host = Arc::new(host);
    let start = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..threads {
        let (ok, rej, err, next, ground, host) = (
            Arc::clone(&ok),
            Arc::clone(&rej),
            Arc::clone(&err),
            Arc::clone(&next),
            Arc::clone(&ground),
            Arc::clone(&host),
        );
        handles.push(std::thread::spawn(move || loop {
            let i = next.fetch_add(1, Ordering::Relaxed) as usize;
            if i >= ground.len() {
                break;
            }
            let (_, hex, nonce) = match ground[i].lock().unwrap().clone() {
                Some(g) => g,
                None => continue,
            };
            let body = format!("{{\"tx_as_hex\":\"{}\",\"pow_stamp\":{}}}", hex, nonce);
            match http(&host, port, "POST", "/submit_pq_tx", Some(&body)) {
                Some(resp) if resp.contains("\"status\":\"OK\"") => {
                    ok.fetch_add(1, Ordering::Relaxed);
                }
                Some(_) => {
                    rej.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    err.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().ok();
    }

    let secs = start.elapsed().as_secs_f64();
    let ok = ok.load(Ordering::Relaxed);
    let rej = rej.load(Ordering::Relaxed);
    let err = err.load(Ordering::Relaxed);
    eprintln!(
        "[tx_flood] DONE in {:.3}s — admitted OK={} rejected={} conn-err={} → {:.0} admitted tx/s (real per-tx WHIR verify at the node, grind excluded)",
        secs, ok, rej, err, ok as f64 / secs.max(1e-9)
    );
}

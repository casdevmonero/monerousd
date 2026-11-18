// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Build script for usdmd-node.
//!
//! PURE-RUST WHIR BY DEFAULT (user 2026-07-13: "100% whir, no monolithic path" + "desktop should also have
//! pq-pouw — this benefits both mobile and desktop"). By default this script links NO native libraries: the node
//! verifies with the SMALL pure-Rust `usdm-decider` WHIR crate (NOT the pqpool_ffi monolith .dylib), and the
//! PoUW puzzle is the pure-Rust Poseidon2-KoalaBear kernel (`crate::pow_pq_kernel`) — the SOLE PoW puzzle on
//! every device; the classical C++ `librandomx.a` fallback was REMOVED (user 2026-07-14: "remove the classical
//! pow fallback"), never linked on any target. A pure-Rust build cross-compiles to `aarch64-apple-ios` (the phone
//! runs its OWN in-process node) AND makes the desktop node leaner + monolith-free. The only remaining OPT-IN
//! native library:
//!   * non-iOS + `libp2p-onion-ffi` feature → link `liblibp2p_ffi.dylib` (the C onion mesh; iOS uses arti).
//! iOS ALWAYS takes the pure-Rust path (nothing native is ever linked there).

use std::path::PathBuf;

fn main() {
    emit_build_stamp();
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_ios = target_os == "ios";

    // ── VERIFY: the pure-Rust `usdm-decider` WHIR light decider, UNCONDITIONALLY (src/whir_decider.rs).
    //    The retired pqpool STARK-era FFI (`libpqpool_ffi.dylib`) is DELETED — never linked on any target
    //    (user 2026-07-14: STARK retired, 100% WHIR).

    // ── ONION MESH: the C `libp2p_ffi` mesh is OPT-IN via `libp2p-onion-ffi` and never linked on iOS (the phone's
    //    in-process node reaches peers through the wallet's embedded arti Tor). Desktop keeps the prebuilt mesh.
    if std::env::var("CARGO_FEATURE_LIBP2P_ONION_FFI").is_ok() && !is_ios {
        let prebuilt = std::env::var("LIBP2P_FFI_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                manifest
                    .join("..")
                    .join("MoneroUSD-clean-local")
                    .join("monero")
                    .join("external")
                    .join("libp2p_ffi")
                    .join("target")
                    .join("release")
            });
        let dir = prebuilt.to_string_lossy();
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=dylib=libp2p_ffi");
        println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        println!("cargo:rerun-if-changed={dir}/liblibp2p_ffi.dylib");
    }

    // ── PoUW = the pure-Rust Poseidon2-KoalaBear kernel (crate::pow_pq_kernel), the ONLY PoW puzzle on every
    //    device (couples to the WHIR prover; no C, no JIT → cross-compiles to iOS). The classical C++
    //    `librandomx.a` link was REMOVED (user 2026-07-14: "remove the classical pow fallback") — MonerousD's
    //    PoW is novel PQ-PoUW, never vestigial-Monero RandomX; no librandomx.a is ever linked, on any target.

    println!("cargo:rerun-if-env-changed=LIBP2P_FFI_DIR");
}

/// ⛔⛔⛔ EVERY BUILD STAMPS ITS OWN BUILD TIME AND SOURCE FINGERPRINT.
///
/// Nothing here carried a build date, so "is this binary running live code?" could only ever be guessed —
/// and guessing wrong cost a whole afternoon: a wallet built from new code was driven against a node binary
/// built from old code, and the resulting rejections were blamed on the protocol through two wrong diagnoses.
/// A user hits the same wall in a worse form: an app that looks current, behaves like an old one, and gives
/// them no way to tell.
///
/// The fingerprint is over the SOURCE, not the clock, so it changes iff the code changed. The timestamp says
/// WHEN, the fingerprint says WHAT — together they make staleness visible instead of inferable.
fn emit_build_stamp() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=MONEROUSD_BUILD_UNIX={secs}");

    // ...and the same instant as a HUMAN-READABLE UTC stamp. A unix integer answers "is this binary current?"
    // only after someone converts it, so in practice nobody does — and a stale binary keeps being blamed on
    // the protocol. `2026-07-28 23:14:02Z` is legible at a glance in `/get_info`, in a log line, and in a
    // screenshot. Computed here with plain civil-calendar arithmetic (days->y/m/d via the standard
    // days-from-civil inverse) so the build script pulls in no dependency for it.
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    println!(
        "cargo:rustc-env=MONEROUSD_BUILD_TIME={y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );

    // Source fingerprint: every .rs under src/, hashed by (path, len, mtime). Cheap, and it moves the instant
    // any source moves — which is precisely the question "is this build current?" asks.
    let mut acc: u64 = 0xcbf29ce484222325;
    let mut stack = vec![std::path::PathBuf::from("src")];
    let mut files = 0u64;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort(); // deterministic: directory order is not stable across filesystems
        for path in entries {
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            files += 1;
            let mut feed = path.display().to_string();
            if let Ok(m) = std::fs::metadata(&path) {
                feed.push_str(&m.len().to_string());
                if let Ok(t) = m.modified().and_then(|t| {
                    t.duration_since(UNIX_EPOCH)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                }) {
                    feed.push_str(&t.as_secs().to_string());
                }
            }
            for b in feed.as_bytes() {
                acc ^= *b as u64;
                acc = acc.wrapping_mul(0x100000001b3);
            }
        }
    }
    println!("cargo:rustc-env=MONEROUSD_SRC_FINGERPRINT={acc:016x}");
    println!("cargo:rustc-env=MONEROUSD_SRC_FILES={files}");
    // Re-run whenever any source changes, so the stamp can never go stale while the binary is rebuilt.
    println!("cargo:rerun-if-changed=src");
}

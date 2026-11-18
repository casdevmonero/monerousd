//! MonerousD Protocol — usdm-decider build script: THE PROVER SOURCE DIGEST, fixed at BUILD time (K1, 2026-09-30).
//!
//! ⛔ WHY AT BUILD TIME (lane-db224-carriage, 06:29): `prover_fingerprint::prover_source_digest` used to walk the tree
//! when the TEST PROCESS started. A binary built before a decider edit and run after it keyed its cached proofs under
//! the POST-edit digest while proving with the PRE-edit prover — the next binary then HIT those proofs: exactly the
//! masking K1 exists to refuse. The digest must name the sources the binary was COMPILED from, so it is computed here
//! and compiled in as `USDM_PROVER_SOURCE_DIGEST`; cargo re-runs this script whenever a hashed file under `vendor/Plonky3`
//! (every crate but `usdm-agg`, which depends on this one), the node lockfile or the compiler changes.
//!
//! O1-INFINITY-REVIEWED: this runs at COMPILE time on a developer machine and reads the prover's own SOURCE files to
//! hash them; no node runs it, it reads no chain state, and nothing it produces is consensus authority — the digest only
//! keys a test-time proof cache (`prover_fingerprint`, test support).
//!
//! Spelling: blake3 over `"MUSD/prover-source/v1"`, then for every `*.rs` and `Cargo.toml` under `vendor/Plonky3`
//! (sorted, `target` dirs and `usdm-agg` skipped) its path relative to the node root followed by its bytes, then the node's
//! `Cargo.lock`, the Plonky3 workspace `Cargo.lock` when present, `rustc -V` and whether debug assertions are on.
//! `none` when the tree is unreadable — the runtime then reports no fingerprint, and a cache with no fingerprint is off.

use std::path::{Path, PathBuf};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    for entry in rd {
        let Ok(entry) = entry else { return false };
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).map(str::to_owned);
        if path.is_dir() {
            // `target` holds build output; `usdm-agg` DEPENDS on this crate and is no part of its prover (MEASURED
            // 2026-11-15, lane agg: hashing it made every tree edit a full ~20-minute decider rebuild under load)
            if name.as_deref() != Some("target") && name.as_deref() != Some("usdm-agg") && !walk(&path, out) {
                return false;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") || name.as_deref() == Some("Cargo.toml") {
            out.push(path);
        }
    }
    true
}

fn digest() -> Option<String> {
    let decider = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    let plonky3 = decider.parent()?.to_path_buf();
    let node_root = plonky3.parent()?.parent()?.to_path_buf();
    println!("cargo:rerun-if-changed={}", node_root.join("Cargo.lock").display());
    println!("cargo:rerun-if-changed={}", plonky3.join("Cargo.lock").display());
    println!("cargo:rerun-if-env-changed=RUSTC");
    let mut files = Vec::new();
    if !walk(&plonky3, &mut files) {
        return None;
    }
    files.sort();
    // re-run on exactly the FILES hashed — never a directory: cargo scans a watched directory recursively, and the
    // Plonky3 root holds usdm-agg (MEASURED 2026-11-16: watching the root's directory still rebuilt the decider on every
    // tree edit). A new source file is reached through a `mod` line in a hashed file, which changes.
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/prover-source/v1");
    for f in &files {
        h.update(f.strip_prefix(&node_root).ok()?.to_string_lossy().as_bytes());
        h.update(&std::fs::read(f).ok()?); // O1-INFINITY-REVIEWED: compile-time hash of the prover's own source files
    }
    h.update(&std::fs::read(node_root.join("Cargo.lock")).ok()?);
    if let Ok(lock) = std::fs::read(plonky3.join("Cargo.lock")) {
        h.update(&lock);
    }
    let rustc = std::env::var_os("RUSTC")?;
    let version = std::process::Command::new(rustc).arg("-V").output().ok()?;
    if !version.status.success() {
        return None;
    }
    h.update(&version.stdout);
    h.update(&[u8::from(std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some())]);
    Some(h.finalize().to_hex().to_string())
}

fn main() {
    let d = match digest() {
        Some(hex) => hex,
        None => String::from("none"),
    };
    println!("cargo:rustc-env=USDM_PROVER_SOURCE_DIGEST={d}");
    // ⭐ SPEED G1 (lane speed4, 2026-11-12): on Apple targets, the Metal plumbing the prover's GPU kernels run through
    // (`src/gpu/metal_shim.m`; the kernel SOURCE is Rust in `src/gpu_grind.rs`, inside the digest above). Elsewhere
    // nothing is compiled and the prover runs on the CPU exactly as before.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" || os == "ios" {
        println!("cargo:rerun-if-changed=src/gpu/metal_shim.m");
        cc::Build::new().file("src/gpu/metal_shim.m").flag("-fobjc-arc").compile("musd_metal_shim");
        println!("cargo:rustc-link-lib=framework=Metal");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}

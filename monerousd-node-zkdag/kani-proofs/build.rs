// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The one `crate::cover` constant `economics.rs` reads is taken from the node's own `src/cover.rs` at build time,
//! so the proofs run at the production value and cannot drift from it. Not found ⇒ the build fails.
fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../src/cover.rs");
    println!("cargo:rerun-if-changed={path}");
    let src = std::fs::read_to_string(path).expect("read ../src/cover.rs");
    let line = src
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("pub const TX_FIXED_NULLIFIER_COUNT: usize ="))
        .expect("src/cover.rs no longer defines TX_FIXED_NULLIFIER_COUNT as a usize literal");
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("cover_shim.rs");
    std::fs::write(out, format!("{line}\n")).unwrap();
}

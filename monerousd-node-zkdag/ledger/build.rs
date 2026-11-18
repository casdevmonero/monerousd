// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Build script for usdm-ledger (node split stage B, lane dcash 2026-11-11): with the `test-hooks` feature — turned on by the
//! node's DEV-dependency only — the ledger is compiled with `cfg(test)`, so its `#[cfg(test)]` hooks are present for the node's
//! tests exactly as they were when the ledger was part of the node crate under test. A release build never sets it.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // the Kani proof harnesses (peg, validator_activity) are compiled only by `cargo kani`, which sets `cfg(kani)`
    println!("cargo::rustc-check-cfg=cfg(kani)");
    if std::env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some() {
        println!("cargo:rustc-cfg=test");
    }
}

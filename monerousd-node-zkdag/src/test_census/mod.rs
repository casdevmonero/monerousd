// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — THE TEST CENSUS RECORDERS PRODUCTION CODE CALLS (lane dcash, 2026-11-11): the three pieces of the adversarial
//! harness that the node's own `#[cfg(test)]` hooks call — the vacuity recorder (`vacuity::record`, a consensus gate's decision
//! counted as real or vacuous), the simulator's coverage recorder (`sim_coverage::note`, every route and wire kind it drove) and the
//! production-source reader (`node_production_source`, the census pins' view of node.rs and its production submodules).
//! WHY HERE: the harness (46k lines) was `#[cfg(test)]`, so EVERY test build compiled it, the light `pins-core` / `pins-node` builds
//! included, because these hooks named it. They live here, always compiled for tests and dependency-free; the harness re-exports them,
//! so every `crate::harness::…` path inside it keeps working, and the harness itself compiles only under the `pins-harness` feature.

pub mod sim_coverage;
/// The vacuity recorder lives in the ledger crate (its gates call it); one set of counters, re-exported here.
pub mod vacuity {
    pub use usdm_ledger::test_census::vacuity::*;
    #[cfg(all(test, feature = "pins-harness"))]
    #[path = "node_tests.rs"]
    mod tests;
}

/// ⭐ THE NODE'S PRODUCTION SOURCE: `src/node.rs` plus every `src/node/<name>.rs` it declares as a `mod <name>;` that is
/// NOT under a test `cfg` — `impl Node` is split across those files, so a reader of `node.rs` alone sees a fraction of the
/// methods. MEASURED 2026-10-29: after `peg_in_confidential` moved to `node/value.rs` the minting-function reader found 0
/// functions and three census pins went red on main. `None` if node.rs cannot be read.
#[must_use]
pub fn node_production_source() -> Option<String> {
    let node = std::fs::read_to_string("src/node.rs").ok()?;
    let mut all = node.clone();
    let lines: Vec<&str> = node.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        let decl = t.strip_prefix("#[cfg(test)] ").unwrap_or(t);
        let Some(name) = decl
            .strip_prefix("mod ")
            .or_else(|| decl.strip_prefix("pub mod "))
            .or_else(|| decl.strip_prefix("pub(crate) mod "))
            .and_then(|r| r.strip_suffix(';'))
        else {
            continue;
        };
        // a test module: the cfg on the same line, or the nearest attribute lines above it
        let mut test = t.starts_with("#[cfg(test)]");
        let mut j = i;
        while j > 0 && lines[j - 1].trim().starts_with("#[") {
            j -= 1;
            let a = lines[j].trim();
            test |= a == "#[cfg(test)]" || a.starts_with("#[cfg(all(test");
        }
        if !test {
            if let Ok(sub) = std::fs::read_to_string(format!("src/node/{name}.rs")) {
                all.push('\n');
                all.push_str(&sub);
            }
        }
    }
    Some(all)
}

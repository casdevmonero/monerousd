// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §19.6 — THE FLASH-LOAN PRICE CENSUS (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §19.6; user 2026-10-29: "our bridge must
//! have flash loan defense").
//!
//! A flash loan wins only where a door reads a figure the borrower can move inside the same batch: a spot price, an order
//! book's best quote, a pool's ratio. MonerousD's value-moving doors read only manipulation-proof prices — the 7-day TWAP
//! over CLOSED epochs (`PegLedger::twap7`), the 30-day low (`low30`), the oracle mark only inside a band of the TWAP
//! (`liquidation_rule`), and the §18 batch price. This census makes that a property of the SOURCE, so code written later —
//! DSOL's planned synchronous calls and flash swaps, a DEX-derived oracle — cannot quietly add a movable read:
//!
//! 1. **The live mark** (`price_marks.get(`, `price_mark_for(`) is read only by the named readers below, each with the
//!    reason it is safe; any other production read is a finding.
//! 2. **No DEX-derived price** (`best_bid`, `best_ask`, `mid_price`, `last_fill_price`, `spot_price`, `pool_price`) in any
//!    value-moving module (the peg, its pool, liquidation, bonds and stake, both payout lanes, the price lanes).
//! 3. **DSOL serves no live price**: the contract surface (`dsol*.rs`) reads neither the live mark nor a DEX-derived price.
//!
//! Borrowed shape: MakerDAO's Oracle Security Module and Uniswap v2/v3's TWAP oracles — a protocol reads a time-averaged
//! price that one block cannot move. The census is a source scan like `harness::surface_census`; its calibration plants a
//! violation of each rule and proves the scan finds it (refutation before green).
//!
//! TWO-PARTY-REVIEWED: a source census over this crate's own text — it has no second endpoint; the doors it audits are
//! two-party-pinned where they live (`peg::tests`, `node::pins`).

use std::path::{Path, PathBuf};

/// The tokens that read the LIVE oracle mark.
pub const LIVE_MARK_TOKENS: &[&str] = &["price_marks.get(", "price_mark_for("];
/// The tokens that would read a price a same-batch trade can move.
pub const DEX_PRICE_TOKENS: &[&str] = &["best_bid", "best_ask", "mid_price", "last_fill_price", "spot_price", "pool_price"];
/// The modules that move value against a price (rule 2's scope).
pub const VALUE_MOVING_MODULES: &[&str] = &[
    "peg.rs",
    "peg_pool.rs",
    "peg_attest.rs",
    "liquidation.rs",
    "liquidation_tx.rs",
    "pool_tx.rs",
    "sat_bond_tx.rs",
    "sat_delegation_tx.rs",
    "bond_yield_claim_tx.rs",
    "stake_tx.rs",
    "satoshi.rs",
    "btc_payout.rs",
    "xmr_payout.rs",
    "pot_fill_tx.rs",
    "price_history.rs",
    "price_mark_tx.rs",
    "price_quote.rs",
];

/// The readers allowed to touch the live mark: (file, enclosing fn, why a same-batch trade cannot move what it uses).
pub const LIVE_MARK_READERS: &[(&str, &str, &str)] = &[
    ("peg.rs", "twap7", "before any epoch closes the 7-day average IS the standing mark: a > 2/3 median of operators' OFF-chain quotes, which no on-chain trade moves"),
    ("peg.rs", "low30", "the LOWER of the history and the mark: a mark moved up cannot raise it, and down is the conservative side for repayment"),
    ("peg.rs", "liquidation_rule", "the mark is refused unless it lies within LIQ_TWAP_BAND_BPS of the 7-day TWAP"),
    ("peg.rs", "mark_price_attested", "the WRITER: the > 2/3 bond-weighted median applying a new mark"),
    ("peg.rs", "price_mark_for", "the accessor's own definition"),
    ("node.rs", "price_mark_for", "a delegating accessor; its callers are scanned in their own files"),
    ("node.rs", "due_liquidation", "reads the mark's EPOCH id only, for the close's id — never its price"),
    ("produce.rs", "publish_price_marks_if_quorum", "reads the mark's EPOCH id only, to skip an asset already marked this epoch"),
];

/// One finding: (file, enclosing fn, line number, the line).
pub type Finding = (String, String, usize, String);

/// The production part of a source: every line except the ITEM each `#[cfg(test)]` / `#[cfg(all(test …` attribute marks —
/// a test module, a test-only fn or a test-only field — skipped by brace depth (a braced item) or to its `;`/`,` (a field).
/// MEASURED 2026-10-29: the first version stopped at the FIRST such attribute, which in `peg.rs` is a test-only item near
/// the top, so the census read none of `peg.rs`'s doors — the named-reader check (`twap7` "no longer exists") caught it.
fn production_lines(src: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test") {
            // skip further attributes, then the item they mark
            i += 1;
            while i < lines.len() && lines[i].trim_start().starts_with("#[") {
                i += 1;
            }
            let mut depth: i64 = 0;
            let mut opened = false;
            while i < lines.len() {
                let l = lines[i];
                depth += l.matches('{').count() as i64 - l.matches('}').count() as i64;
                opened |= l.contains('{');
                i += 1;
                if (opened && depth <= 0) || (!opened && (l.trim_end().ends_with(';') || l.trim_end().ends_with(','))) {
                    break;
                }
            }
            continue;
        }
        out.push((i, lines[i]));
        i += 1;
    }
    out
}

/// The name of the `fn` a line opens, if it opens one.
fn fn_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let at = t.find("fn ")?;
    if !t[..at].split_whitespace().all(|w| matches!(w, "pub" | "pub(crate)" | "pub(super)" | "const" | "async" | "unsafe" | "extern")) {
        return None;
    }
    let name: String = t[at + 3..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    (!name.is_empty()).then_some(name)
}

/// ⭐ Scan one source: the findings of the three rules for a file named `file`.
#[must_use]
pub fn scan(file: &str, src: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut current = String::new();
    let value_moving = VALUE_MOVING_MODULES.contains(&file);
    let dsol = file.starts_with("dsol");
    for (i, line) in production_lines(src) {
        if let Some(n) = fn_name(line) {
            current = n;
        }
        let code = line.split("//").next().map_or("", |c| c);
        let live = LIVE_MARK_TOKENS.iter().any(|t| code.contains(t));
        let dex = DEX_PRICE_TOKENS.iter().any(|t| code.contains(t));
        let named = LIVE_MARK_READERS.iter().any(|(f, func, _)| *f == file && *func == current);
        if (live && (dsol || !named)) || (dex && (value_moving || dsol)) {
            out.push((file.to_string(), current.clone(), i + 1, line.trim().to_string()));
        }
    }
    out
}

/// The crate's production sources: `src/*.rs` and `src/node/*.rs`, test files excluded.
fn production_files(src_root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in [src_root.to_path_buf(), src_root.join("node")] {
        let rd = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("the census cannot list {}: {e}", dir.display()));
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).map_or_else(String::new, str::to_string);
            let test_file = name.contains("pins") || name.contains("tests") || name.ends_with("_scenarios.rs");
            if p.extension().is_some_and(|x| x == "rs") && !test_file {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

/// Every finding in the crate's production source. An unreadable source fails the census loudly — a skipped file would
/// hide exactly the read it exists to find.
#[must_use]
pub fn census() -> Vec<Finding> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    production_files(&root)
        .iter()
        .flat_map(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).map_or_else(String::new, str::to_string);
            let src = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("the census cannot read {}: {e}", p.display()));
            scan(&name, &src)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐⭐ §19.6 — EVERY VALUE-MOVING PRICE READ IS A CLOSED-EPOCH TWAP, A BANDED MARK OR A BATCH PRICE: the crate's production
    /// source holds no read of the live mark outside its named readers, no DEX-derived price in a value-moving module, and
    /// no live price on the DSOL contract surface. Every named reader is still present (a renamed reader is re-justified,
    /// never silently dropped from the list).
    #[test]
    fn br_flash_every_value_moving_price_read_is_a_closed_epoch_twap_or_a_batch_clearing_price() {
        let found = census();
        for f in &found {
            eprintln!("[flash-census] {}:{} in fn {} — {}", f.0, f.2, f.1, f.3);
        }
        assert!(found.is_empty(), "⛔ {} read(s) a same-batch trade could move: {:?}", found.len(), found);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for (file, func, _) in LIVE_MARK_READERS {
            let path = if *file == "produce.rs" { root.join("node").join(file) } else { root.join(file) };
            let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            assert!(
                production_lines(&src).iter().any(|(_, l)| fn_name(l).as_deref() == Some(func)),
                "the named reader {file}::{func} no longer exists — re-justify the list"
            );
        }
    }

    /// ⭐⭐⭐ §21 — NO HAND-SET PRICE: no production line reads a price an operator typed (`MONEROUSD_PRICE_QUOTES`, or any
    /// environment variable named for a price); a validator quotes only what its sampled onion relays answer. Calibrated: a
    /// planted read is found and a comment naming the variable is not.
    /// TWO-PARTY-REVIEWED: a source census over this crate's own text — no second endpoint; the quote's two parties (the
    /// quoting validator and the node that gathers its quote into a mark) are pinned in `chain_action_carriage_tests`.
    #[test]
    fn br21_no_production_code_reads_a_hand_set_price() {
        fn hand_set(file: &str, src: &str) -> Vec<Finding> {
            production_lines(src)
                .into_iter()
                .filter(|(_, l)| {
                    let code = l.split("//").next().map_or("", |c| c);
                    code.contains("MONEROUSD_PRICE") || (code.contains("env::var(") && code.to_ascii_uppercase().contains("PRICE"))
                })
                .map(|(i, l)| (file.to_string(), String::new(), i + 1, l.trim().to_string()))
                .collect()
        }
        let planted = "pub fn q() -> Option<u128> {\n    std::env::var(\"MONEROUSD_PRICE_QUOTES\").ok()?.parse().ok()\n}\n// MONEROUSD_PRICE_QUOTES is gone\n";
        assert_eq!(hand_set("x.rs", planted).len(), 1, "calibration: the planted read is found, the comment is not");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let found: Vec<Finding> = production_files(&root)
            .iter()
            .flat_map(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).map_or_else(String::new, str::to_string);
                let src = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                hand_set(&name, &src)
            })
            .collect();
        assert!(found.is_empty(), "⛔ production code reads a hand-set price: {found:?}");
    }

    /// CALIBRATION (refutation before green): a planted violation of each rule is found, in the right function — a new
    /// door reading the live mark, a liquidation module reading an order book's best bid, DSOL serving a spot price — and
    /// a named reader and a test module are not.
    #[test]
    fn the_flash_census_finds_a_planted_live_read_of_each_kind() {
        let door = "pub fn mint_against(&self) -> u128 {\n    let p = self.price_marks.get(&1)?.price;\n}\n";
        assert_eq!(scan("peg.rs", door).len(), 1, "a new door reading the live mark");
        assert_eq!(scan("peg.rs", door)[0].1, "mint_against");
        let liq = "fn close(&self) {\n    let p = book.best_bid();\n}\n";
        assert_eq!(scan("liquidation.rs", liq).len(), 1, "a value-moving module reading an order book");
        assert!(scan("order_book.rs", liq).is_empty(), "the order book itself may name its best bid");
        let dsol = "pub fn host_price(&self) -> u128 {\n    node.price_mark_for(1)\n}\n";
        assert_eq!(scan("dsol.rs", dsol).len(), 1, "DSOL serving the live mark");
        let named = "pub fn liquidation_rule(&self) {\n    let mark = self.price_marks.get(&asset_id)?.price;\n}\n";
        assert!(scan("peg.rs", named).is_empty(), "a named, banded reader is allowed");
        let test_only = "#[cfg(test)]\nmod tests {\n fn t() { let p = self.price_marks.get(&1); }\n}\n";
        assert!(scan("peg.rs", test_only).is_empty(), "test modules are not production reads");
        // a test-only item ABOVE a door must not hide the door (the first version stopped at it)
        let shadowed = "#[cfg(test)]\npub fn seam() -> u64 { 1 }\npub fn later_door(&self) -> u128 {\n    let p = self.price_marks.get(&1)?.price;\n}\n";
        assert_eq!(scan("peg.rs", shadowed).len(), 1, "a door below a test-only item is still scanned");
    }
}

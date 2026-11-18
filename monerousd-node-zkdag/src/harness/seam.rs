// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE SEAM CENSUS — does anything in PRODUCTION actually call this subsystem?
//!
//! ## The defect class, and why a new instrument was needed for it
//!
//! `src/da.rs` held a complete data-availability sampling primitive. Twelve comments across this tree
//! described it as the note store — *"note ciphertexts are peer-sampled DA"*, *"its leaves live in DA"*,
//! *"served from a sharded DA"* — and in PRODUCTION `da::inclusion_proof`, `da::verify_chunk` and
//! `da::sample_indices` had **ZERO callers**. A producer could commit `output_notes_root` and WITHHOLD
//! the bytes, and nothing in the tree could tell. That was a SOUNDNESS gap living behind a wall of
//! comments asserting the opposite (kill list §AM).
//!
//! ⭐ **A SUBSYSTEM CITED BY A DOZEN COMMENTS IS NOT EVIDENCE IT RUNS.** Nothing here checked, because
//! every existing instrument answers a different question:
//!   * `finish-before-testing-guard` catches a symbol built MINUTES ago with no caller. It is
//!     time-windowed, so a seam unwired for months is invisible to it.
//!   * `chain_action_manifest_sweep` catches "this should be a chain action and is not" — route-arm
//!     scoped, and blind to a whole module nobody calls.
//!   * `authority.rs` catches a FIELD with no declared owner, not a MODULE with no caller.
//! None of them asks the question this file asks, which is why the DA gap survived every one of them.
//!
//! ## ⭐⭐⭐ CALIBRATION IS THE POINT, NOT A FORMALITY
//!
//! Two drafts of this census were BROKEN and both printed a clean, plausible list:
//!   1. counting only `module::` paths missed `use crate::m::Type;` + bare `Type::new()`, which made a
//!      2,060-line module with live readers look dead;
//!   2. treating everything after the FIRST `#[cfg(test)]` as test code threw away most of a
//!      42,000-line file, and reported `reward`, `log_cap` and `liquidation` as unwired when the first
//!      two are called in production.
//! So [`the_seam_census_is_calibrated`] runs FIRST against modules verified BY HAND to be wired. A
//! broken census fails there, loudly, instead of certifying an empty result.
//!
//! ⛔ AND CALIBRATE AGAINST WHAT YOU HAVE VERIFIED, NOT WHAT YOU ASSUME. `liquidation` was in the
//! calibration set on the theory that a module about seizing collateral must surely be wired. It is not:
//! every `crate::liquidation::` reference in the tree sits inside `peg.rs`'s own test module. An
//! assumed-wired entry turns a real finding into "the tool is broken".
//!
//! ROOT-LAYER: the module list is read from `lib.rs` and the callers from the filesystem at test time —
//! never from a hand-maintained list of files to scan. A census whose INPUT is hand-written has a blind
//! spot exactly where somebody forgot to add something, which is the same failure it exists to catch.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// What production is expected to do with a module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seam {
    /// Wired, but the caller lives in ANOTHER CRATE of this workspace (the wallet). Verified by
    /// `cross_crate_consumers_are_real`, which reads that crate and refuses a claim it cannot find.
    WiredCrossCrate,
    /// Production calls it. The gate asserts at least one caller, and FAILS if it becomes dead.
    Wired,
    /// Production deliberately does not call it, for the NAMED reason. The gate asserts it is still
    /// uncalled — a seam that quietly becomes wired must be re-declared, so the manifest cannot go
    /// stale in either direction.
    Unwired(&'static str),
}

/// ⭐ EVERY `pub mod` IN `lib.rs` MUST APPEAR HERE. A new module with no entry fails
/// [`every_declared_module_states_whether_production_calls_it`], so a subsystem cannot be added and
/// left unwired in silence — which is exactly how the DA layer sat unused behind a dozen comments.
pub const SEAM_MANIFEST: &[(&str, Seam)] = &[
    // ── DELIBERATELY UNWIRED, each with the reason named. These are the findings of the first census
    // run (2026-09-13); every one is recorded in the kill list as §AN.
    (
        "nullifier_tree",
        Seam::Unwired(
            "THE RETIRED SECOND AUTHORITY. The node's only spent-set field is \
             `sparse_acc: nf_sparse::SparseNfAcc`, and an unspent tree as a SECOND authority was the \
             root of the whole D-3x class — so zero production callers is CORRECT here. ⛔ But \
             `sync.rs` still documents a jumped node as installing into 'its NullifierTree', which is \
             now false, and 2,060 lines of retired authority still compile.",
        ),
    ),
    // ⭐ FLIPPED Unwired -> Wired 2026-09-22, as the gate asked. It reached production while the
    // manifest still called it a test-only twin: `peg.rs` calls `aggregate_solvent` and
    // `aggregate_ratio_bps` on the confidential redeem path, and `price_mark_tx` reads `PRICE_SCALE`
    // as the unit every priced deposit is converted into (DB-124).
    //
    // ⛔ THE HISTORY THIS ENTRY CARRIED IS WORTH KEEPING: its old reason recorded "MY FIRST READING OF
    // THIS WAS WRONG ... 'zero production callers' is a finding to INVESTIGATE, never a verdict." That
    // stays true, and `the_native_solvency_twin_agrees_with_the_rule_the_circuit_proves` still keeps the
    // native predicate honest against the rule the circuit proves.
    ("liquidation", Seam::Wired),
    // ⛔ DECLARED 2026-09-24 — both were in `lib.rs` with NO seam entry, so nothing in the tree stated
    // whether production calls them. Verified by reading the CALL sites, not the citations, which is the
    // distinction this census exists for ("cited everywhere, called nowhere").
    //
    // The ORDER-POST chain object: `rpc_http.rs` builds the tx at the submit door
    // (`order_post_tx::as_pq_tx`) and `node.rs` applies it from the block
    // (`order_post_tx::apply_chain_order_post`). Submit side AND apply side, so an order POST travels as
    // a chain object rather than a local mutation — which is the trustless cardinal's own requirement.
    ("order_post_tx", Seam::Wired),
    // The peg's money arithmetic: `peg.rs` calls `economics::retention_fee_conserves` before a fee moves
    // and `economics::endowment_after_payout` before a payout does. Both are real calls in the value
    // path, not doc references — the file cites `payout_is_funded` in prose as well, and a citation is
    // exactly what this census refuses to count.
    ("economics", Seam::Wired),
    (
        "nf_oblivious",
        Seam::Unwired(
            "PRIVACY SURFACE, BUILT AND UNUSED: oblivious nullifier lookup. Until something calls it, \
             a which-item nullifier query has no oblivious path to take.",
        ),
    ),
    (
        "mix",
        Seam::Unwired("PRIVACY SURFACE, BUILT AND UNUSED. No production path mixes."),
    ),
    // ⭐ FLIPPED Unwired -> Wired 2026-09-22, as the gate asked. The old reason ("`btc_watch` is wired
    // and this is not") describes a state that ended when the XMR leg went green on real nodes
    // (DB-121x run 5): `rpc_http`, `node` and `xmr_payout` all call it now.
    ("xmr_watch", Seam::Wired),
    // ⭐⭐⭐ WIRED — BY A CONSUMER IN ANOTHER CRATE, which is why this sat filed as dead.
    //
    // ⛔⛔⛔ THE BLIND SPOT THIS ENTRY IS THE RECORD OF. `ble_frame` was reported Unwired and the reason
    // written here said "no node path speaks it" — every word true of THIS crate, and the wrong
    // conclusion. `BleCellPump` is constructed over `serve::ble_bridge()` at TWO live sites in
    // `monerousd-wallet-v2/src-tauri/src/moneropay_ble.rs` (the GATT central and peripheral roles) and
    // DRIVEN in both directions (`drive_outbound` / `on_fragment`). The node composes that same
    // `ble_bridge()` leg into its `MultiTransport` on every boot, so the transport is live end to end.
    //
    // The census scanned `<node>/src` alone, so a subsystem whose only consumer is the WALLET reads as
    // dead — the split-impl blind spot's sibling on a different axis, and the same near-miss: this was
    // filed as a gap to CLOSE, and closing a gap that is not there usually means deleting something.
    ("ble_frame", Seam::WiredCrossCrate),
    (
        "test_standard",
        Seam::Unwired("TEST SCAFFOLDING by design — it has no business in a production path."),
    ),
    // ── WIRED. The gate fails if any of these loses its last production caller.
    // §BA/§BB — laid by `Node::lay_note_transition` at produce, verified in `ingest_block`, and read by
    // `graft_admitted_notes` to build the ALLOW-list a peer judges a block's notes with.
    ("note_transition", Seam::Wired),
    ("account_da", Seam::Wired),
    ("address", Seam::Wired),
    ("arti_transport", Seam::Wired),
    ("asset_tx", Seam::Wired),
    ("block", Seam::Wired),
    ("bridge", Seam::Wired),
    ("bridge_credit_tx", Seam::Wired),
    ("btc_watch", Seam::Wired),
    ("chain_object", Seam::Wired),
    ("clue_registry", Seam::Wired),
    ("consensus", Seam::Wired),
    ("cover", Seam::Wired),
    ("da", Seam::Wired),
    ("dag", Seam::Wired),
    ("decider", Seam::Wired),
    ("directory", Seam::Wired),
    ("dsol", Seam::Wired),
    ("faucet", Seam::Wired),
    ("governance", Seam::Wired),
    // ⭐ WIRED BY SPLIT IMPL: this file is `impl Dag { pub fn ghostdag_data(..) }` and `dag.rs` calls it
    // on every block as `self.ghostdag_data(..)`. It has no module path and no import BY CONSTRUCTION,
    // which is why the census called it dead until it learned about split impls.
    ("ghostdag", Seam::Wired),
    ("hash", Seam::Wired),
    ("letter", Seam::Wired),
    ("lifecycle", Seam::Wired),
    ("liquidation_tx", Seam::Wired),
    ("log_cap", Seam::Wired),
    ("mempool", Seam::Wired),
    ("merkle", Seam::Wired),
    ("miner", Seam::Wired),
    ("names", Seam::Wired),
    ("net", Seam::Wired),
    ("nf_sparse", Seam::Wired),
    ("node", Seam::Wired),
    ("node_runtime", Seam::Wired),
    ("note_scan", Seam::Wired),
    ("oli", Seam::Wired),
    ("omr", Seam::Wired),
    ("onion_transport", Seam::Wired),
    ("order_book", Seam::Wired),
    ("order_fill_tx", Seam::Wired),
    ("params", Seam::Wired),
    ("peer_directory", Seam::Wired),
    ("peg", Seam::Wired),
    ("persist", Seam::Wired),
    ("node_files", Seam::Wired), // DB-341's one state dir: persist re-exports it, the validator's key path reads it
    ("pouw", Seam::Wired),
    ("pow", Seam::Wired),
    ("pow_pq_kernel", Seam::Wired),
    ("bond_tally", Seam::Wired),
    ("pqauth", Seam::Wired),
    ("pqkem", Seam::Wired),
    ("protocol", Seam::Wired),
    ("psm", Seam::Wired),
    ("relay", Seam::Wired),
    ("reward", Seam::Wired),
    ("rpc", Seam::Wired),
    ("rpc_http", Seam::Wired),
    ("serve", Seam::Wired),
    ("settlement", Seam::Wired),
    ("site", Seam::Wired),
    ("solvency", Seam::Wired),
    ("sovereign", Seam::Wired),
    ("spend_frontier", Seam::Wired),
    ("sync", Seam::Wired),
    ("tor_supervisor", Seam::Wired),
    ("transport", Seam::Wired),
    // ⭐ §AS — the unbond object. Wired at four production sites: `chain_object::{carried_note_payloads,
    // admissible}`, `Node::publish_unbond`, and `Node::apply_bond_set`, which is where the release travels.
    ("unbond_tx", Seam::Wired),
    ("validator", Seam::Wired),
    ("vdf_clock", Seam::Wired),
    ("whir_decider", Seam::Wired),
    ("wrapped_asset_tx", Seam::Wired),
    // ── The BTC/XMR bridge legs and the persisted window. Added 2026-09-22: they were declared in
    // `lib.rs` with NO entry at all, which is exactly what this gate exists to refuse. Caller counts
    // measured over live `.rs` only (excluding the module itself, harness, `_tests.rs`, `scenarios.rs`).
    ("block_window", Seam::Wired),
    ("btc_tx", Seam::Wired),
    ("btc_payout", Seam::Wired),
    ("xmr_rpc", Seam::Wired),
    ("xmr_custody", Seam::Wired),
    ("xmr_payout", Seam::Wired),
    ("peg_pool", Seam::Wired),
    (
        "btc_regtest",
        Seam::Unwired(
            "A REGTEST DRIVER, not a production path: it spins a local bitcoind in regtest to drive the \
             BTC exit leg end to end (DB-121's green run). Production reaches Bitcoin through `btc_tx`, \
             `btc_watch` and `btc_payout`, which ARE wired. Nothing in a shipping node may start a \
             regtest chain, so zero production callers is the correct state, not a hole.",
        ),
    ),
    (
        "xmr_regtest",
        Seam::Unwired(
            "The Monero mirror of `btc_regtest`, unwired for the identical reason: it drives a local \
             monerod/wallet-rpc to prove the XMR leg (DB-121x run 5). Production reaches Monero through \
             `xmr_rpc`, `xmr_watch`, `xmr_custody` and `xmr_payout`, all wired.",
        ),
    ),
    // DB-124's price mark. Wired: `apply_chain_price_mark` is called from the block-apply loop in
    // `node.rs` beside every other attested class, and `PegLedger::mint_is_covered_by_priced_deposit`
    // is read at the custodian's sign decision. A mark that nothing applied would be the exact
    // "cited everywhere, called nowhere" shape this census exists to catch.
    ("price_mark_tx", Seam::Wired),
    ("wrapped_mint_tx", Seam::Wired),
    // ── §CS / §CL (2026-09-16): the three classes that turned a LOCAL MUTATION into a chain object.
    // Each is wired at BOTH halves in `node.rs` — the frame half where the node publishes
    // (`peg_in_tx::wire` at 18324, `peg_out_tx::wire` at 18432, `yield_claim_tx::wire` at 20399) and the
    // APPLY half every peer runs at graft (`apply_chain_peg_in` at 23980 and its two twins).
    //
    // ⛔ WIRED IS NOT PROVEN. §CV measured that `apply_chain_peg_in` has ZERO test callers in `src/` OR
    // `tests/` — production is its only caller. This gate answers "does anything call it?", never "has
    // anyone watched it run"; the e2e register answers the second and says `Moved::Unproven` for all
    // three. Do not read a `Wired` here as coverage.
    // ⭐ §CW closure — the validator SEAT as a chain object. Wired at both halves: `publish_membership_bond`
    // frames + pools it (serve.rs / main.rs on MONEROUSD_VALIDATOR_BOND), and `apply_bond_set` runs
    // `apply_chain_membership_bond` on every grafting node. Free while the reserve is zero.
    ("membership_bond_tx", Seam::Wired),
    // ⭐ THE PEG-IN ATTESTATION LANE — wired at four halves: `Node::propose_peg_in` + `/peg_in_execute`
    // (executor), `NodeRuntime::answer_peg_attest_request` → `Node::attest_peg_in` (custodian), the two
    // `WireMsg::PegAttestReq/Resp` gossip arms (every node), and `advance_custodian_opening_from_delta`
    // at graft. Before it a second seated validator made every mint INSUFFICIENT_THRESHOLD.
    ("peg_attest", Seam::Wired),
    ("peg_in_tx", Seam::Wired),
    ("peg_out_tx", Seam::Wired),
    // `yield_claim_tx` LEFT 2026-10-04: the module no longer exists (DB-237 made the yield claim a `stake_tx` object,
    // `Class::YieldClaim` decodes through `stake_tx::decode`); its row read as a wired seam with zero callers.
    // ── The modules the census found unlisted on 2026-10-04 (MEASURED: 12 declared in lib.rs with no row). Each is
    // production code the node calls; `every_wired_seam_has_a_production_caller` refuses any that is not.
    ("member_transition", Seam::Wired),
    ("member_witness", Seam::Wired),
    ("window_index", Seam::Wired),
    ("local_origin", Seam::Wired),
    ("respend", Seam::Wired),
    ("keystore", Seam::Wired),
    ("stake_tx", Seam::Wired),
    ("pool_tx", Seam::Wired),
    ("price_quote", Seam::Wired),
    ("equivocation_tx", Seam::Wired),
    ("theft_tx", Seam::Wired),
    ("vote_guard", Seam::Wired),
];

/// Modules verified BY HAND to have production callers. If the census reports any of them as dead it is
/// BROKEN, and must fail there rather than certify a clean sweep.
const CALIBRATION_WIRED: &[&str] =
    &["reward", "log_cap", "da", "cover", "mempool", "block", "spend_frontier", "pow",
      // ⭐ `ghostdag` IS IN THIS SET DELIBERATELY. It is reached only as `impl Dag`, so it is the
      // canary for the split-impl blind spot — the one that nearly cost 426 lines of consensus ordering.
      "ghostdag"];

fn src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` under `src/`, read from the FILESYSTEM rather than from a hand-written list — a census
/// whose input is hand-maintained is blind exactly where somebody forgot to add something.
/// Backups (`foo.rs.preX-YYYYMMDD`) are skipped: they are not compiled and their callers are not real.
fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &PathBuf, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let name = p.to_string_lossy().to_string();
                if name.contains(".rs.") {
                    continue; // a backup, not a compiled file
                }
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    out.push((name, txt));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&src_root(), &mut out);
    out
}

/// Is this file test scaffolding rather than production?
fn is_test_file(path: &str) -> bool {
    path.ends_with("_tests.rs")
        || path.contains("/harness/")
        || path.ends_with("_scenarios.rs")
}

/// ⛔ REMOVE EVERY `#[cfg(test)]` ITEM BY BRACE-MATCHING IT — never by truncating at the first one.
/// Truncating is the obvious implementation and it is wrong: `node.rs` has test-only helpers scattered
/// through 42,000 lines, so a truncating census throws most of the file away and reports live modules as
/// dead. MEASURED: that draft called `reward`, `log_cap` and `liquidation` unwired; the first two are
/// called in production.
fn strip_test_spans(txt: &str) -> String {
    let mut out = String::with_capacity(txt.len());
    let b = txt.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = txt[i..].find("#[cfg(test)]") {
        let j = i + rel;
        out.push_str(&txt[i..j]);
        let brace = txt[j..].find('{').map(|k| j + k);
        let semi = txt[j..].find(';').map(|k| j + k);
        match (brace, semi) {
            // an attributed `use ...;` / `const ...;` — skip to its semicolon
            (Some(bp), Some(sp)) if sp < bp => i = sp + 1,
            (None, Some(sp)) => i = sp + 1,
            (Some(bp), _) => {
                let mut depth = 0i32;
                let mut p = bp;
                while p < b.len() {
                    match b[p] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    p += 1;
                }
                i = (p + 1).min(txt.len());
            }
            (None, None) => {
                i = j + "#[cfg(test)]".len();
            }
        }
    }
    out.push_str(&txt[i.min(txt.len())..]);
    out
}

fn strip_comment_lines(txt: &str) -> String {
    txt.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// How many times PRODUCTION code refers to `module` — by path (`m::`) or by import (`use ..m::`).
/// ⛔ BOTH FORMS COUNT. `use crate::m::Type;` followed by a bare `Type::new()` is wiring, and a census
/// that counts only paths reports a module with a dozen live readers as dead.
fn production_refs(module: &str, files: &[(String, String)]) -> usize {
    let own_a = format!("/{module}.rs");
    let own_b = format!("/{module}/mod.rs");
    let path = format!("{module}::");
    let mut n = 0usize;
    for (p, txt) in files {
        if p.ends_with(&own_a) || p.ends_with(&own_b) || is_test_file(p) {
            continue;
        }
        let body = strip_comment_lines(&strip_test_spans(txt));
        for line in body.lines() {
            for (k, _) in line.match_indices(&path) {
                let before = line[..k].chars().next_back();
                // `nf_sparse::` must not count as a hit for `sparse`, nor `liquidation_tx::` for
                // `liquidation` — a prefix match here would certify a dead module as live.
                if !matches!(before, Some(c) if c.is_alphanumeric() || c == '_') {
                    n += 1;
                }
            }
        }
    }
    n
}

/// ⛔⛔⛔ THE THIRD BLIND SPOT, AND THE ONE THAT NEARLY DELETED THE CONSENSUS ORDERING.
///
/// A module may contain nothing but `impl SomeType { .. }` for a type declared in ANOTHER file. Such a
/// module has ZERO `module::` paths and ZERO `use module::` imports BY CONSTRUCTION — its methods are
/// reached through the TYPE, as `self.method()`. A path-based census calls it dead.
///
/// MEASURED: `src/ghostdag.rs` is `impl Dag { pub fn ghostdag_data(..) }`, and `dag.rs` calls it on
/// every block as `self.ghostdag_data(&header.parents)`. The census reported it as having zero callers
/// and I was one step from deleting 426 lines of GHOSTDAG — the ordering every block's blue score comes
/// from. ⭐ **A DETECTOR'S FINDING IS A HYPOTHESIS. Verify the mechanism before acting on it.**
///
/// So: a module that impls a FOREIGN type (one it does not declare) is wired whenever that type is used
/// in production. `ghostdag` is now in the calibration set, so this blind spot cannot silently return.
fn foreign_impl_targets(own_src: &str) -> Vec<String> {
    let declared: Vec<String> = own_src
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            for kw in ["pub struct ", "pub enum ", "struct ", "enum ", "pub trait ", "trait "] {
                if let Some(r) = t.strip_prefix(kw) {
                    let name: String =
                        r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            None
        })
        .collect();
    let mut out = Vec::new();
    for l in own_src.lines() {
        let t = l.trim_start();
        if !t.starts_with("impl") {
            continue;
        }
        // `impl Foo {`, `impl<T> Foo<T> {`, `impl Trait for Foo {` — take the type being implemented.
        let after = t.trim_start_matches("impl").trim_start();
        let after = if after.starts_with('<') {
            after.split_once('>').map(|(_, r)| r.trim_start()).unwrap_or(after)
        } else {
            after
        };
        let target = if let Some((_, r)) = after.split_once(" for ") { r } else { after };
        let name: String = target.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if !name.is_empty() && !declared.contains(&name) && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Is `ty` used anywhere in production outside `own`? Evidence that a split-impl module is reachable.
fn type_used_in_production(ty: &str, own: &[String], files: &[(String, String)]) -> bool {
    let pat = format!("{ty}");
    files.iter().any(|(p, txt)| {
        if own.iter().any(|o| p.ends_with(o.as_str())) || is_test_file(p) {
            return false;
        }
        strip_comment_lines(&strip_test_spans(txt)).lines().any(|line| {
            line.match_indices(&pat).any(|(k, _)| {
                let before = line[..k].chars().next_back();
                let after = line[k + pat.len()..].chars().next();
                !matches!(before, Some(c) if c.is_alphanumeric() || c == '_')
                    && !matches!(after, Some(c) if c.is_alphanumeric() || c == '_')
            })
        })
    })
}

fn census(files: &[(String, String)]) -> BTreeMap<String, usize> {
    declared_modules()
        .into_iter()
        .map(|m| {
            let mut c = production_refs(&m, files);
            if c == 0 {
                // A SPLIT IMPL has no module path by construction — check the type instead.
                let own_a = format!("/{m}.rs");
                let own_b = format!("/{m}/mod.rs");
                let own: Vec<String> = vec![own_a.clone(), own_b.clone()];
                if let Some((_, src)) =
                    files.iter().find(|(p, _)| p.ends_with(&own_a) || p.ends_with(&own_b))
                {
                    for ty in foreign_impl_targets(src) {
                        if type_used_in_production(&ty, &own, files) {
                            c += 1;
                        }
                    }
                }
            }
            (m, c)
        })
        .collect()
}

/// Every `pub mod x;` in `lib.rs` AND in `ledger_lib.rs` — the subsystems this crate declares it has, its own and the ledger
/// crate's (node split stage B, lane dcash 2026-11-11: the ledger modules are declared in `ledger_lib.rs` and re-exported by
/// `lib.rs`, so a census that read `lib.rs` alone would have lost two thirds of its subject).
fn declared_modules() -> Vec<String> {
    let mut lib = std::fs::read_to_string(src_root().join("lib.rs")).expect("lib.rs is readable");
    lib.push('\n');
    // only the ledger crate's ROOT declarations (column 0): a module nested in an inline block is not a subsystem of its own
    let ledger = std::fs::read_to_string(src_root().join("ledger_lib.rs")).expect("ledger_lib.rs is readable");
    for l in ledger.lines().filter(|l| l.starts_with("pub mod ")) {
        lib.push_str(l);
        lib.push('\n');
    }
    lib.lines()
        .filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("pub mod ")
                .and_then(|r| r.split(';').next())
                .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
                .map(str::to_string)
        })
        .collect()
}

/// ⭐⭐⭐ THE USER'S OWN FORMULATION, MADE MEASURABLE: *"the DA layer having 0 callers yet being mentioned
/// everywhere as important and beneficial is itself a harness gap."*
///
/// **CITED-AS-LOAD-BEARING + CALLED-BY-NOTHING is a far sharper signal than zero callers alone.** Plenty
/// of modules are legitimately uncalled — a retired authority, a wallet-side helper, a bridge watcher.
/// What made `da.rs` dangerous was that the rest of the tree WROTE ABOUT IT AS IF IT RAN: other files'
/// doc comments referred to `crate::da::…` eighteen times across five files while nothing called it.
/// Every one of those citations is a reviewer being told the mechanism is live.
///
/// ⛔ AND THE FIRST VERSION OF THIS COUNTER WAS A FALSE-POSITIVE MACHINE. Counting the bare WORD put
/// `liquidation` at 53 — above `da` — because "liquidation" is the domain concept `peg.rs` is about, and
/// the `crate::liquidation` MODULE is named once. Counting only CODE references (`crate::m`, `m::`) puts
/// it at 5 and `da` at 18. ⭐ **THE SAME LESSON AS `ghostdag`: measure the mechanism, not the word.**
fn doc_citations(module: &str, files: &[(String, String)]) -> usize {
    let own_a = format!("/{module}.rs");
    let own_b = format!("/{module}/mod.rs");
    let qualified = format!("crate::{module}");
    let path = format!("{module}::");
    let mut n = 0usize;
    for (p, txt) in files {
        if p.ends_with(&own_a) || p.ends_with(&own_b) || is_test_file(p) {
            continue;
        }
        for line in txt.lines() {
            let t = line.trim_start();
            if !(t.starts_with("//") || t.starts_with('*')) {
                continue; // a CITATION is prose about the module; a call is counted elsewhere
            }
            // ⛔⛔ A PREFIX IS NOT A NAME. The first build of this counter did `matches("crate::liquidation")`
            // and scored 12, because `crate::liquidation_tx` — a DIFFERENT module — starts with it. That
            // is the `ghostdag` lesson a fourth time in one instrument: **match the mechanism, not the
            // substring.** The real count is 5, below the threshold, and the gate correctly stays quiet.
            let mut q = 0usize;
            while let Some(k) = t[q..].find(&qualified) {
                let at = q + k;
                let after = t[at + qualified.len()..].chars().next();
                if !matches!(after, Some(c) if c.is_alphanumeric() || c == '_') {
                    n += 1;
                }
                q = at + qualified.len();
            }
            // `m::` not already counted as part of `crate::m::`, and not a longer identifier ending in m
            let mut from = 0usize;
            while let Some(k) = t[from..].find(&path) {
                let at = from + k;
                let before = t[..at].chars().next_back();
                let word = !matches!(before, Some(c) if c.is_alphanumeric() || c == '_' || c == ':');
                if word {
                    n += 1;
                }
                from = at + path.len();
            }
        }
    }
    n
}

/// The line between "peripheral and uncalled" and "documented as load-bearing and uncalled".
/// MEASURED 2026-09-13: `da` 18 · `pow` 12 (wired, the control) · every genuinely peripheral unwired
/// module ≤ 5. Six sits in the gap, well below the historical case this gate exists to have caught.
const CITED_AS_LOAD_BEARING: usize = 6;

/// The marker a heavily-cited unwired seam's reason must carry, so filing one is a DELIBERATE, reviewed
/// act and never a one-line dismissal.
const CITED_MARKER: &str = "CITED-BUT-UNCALLED:";

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE DECIDER CENSUS — the same question one level down, and the level the DA gap actually lived at.
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// ⛔⛔⛔ THE MODULE CENSUS ABOVE WOULD NOT HAVE FOUND THE GAP THAT PROMPTED IT.
///
/// `src/da.rs` had `commit` wired, so the module had production callers and the census would have
/// filed it `Wired` and moved on. The hole was one level down: `inclusion_proof`, `verify_chunk` and
/// `sample_indices` — the three functions that make availability SAMPLED rather than ASSUMED — had
/// zero callers each, behind a dozen comments calling the module the note store.
///
/// ⭐⭐⭐ **A SUBSYSTEM IS NOT WIRED BECAUSE SOMETHING IN IT IS CALLED.** The unit that has to be wired
/// is the function that DECIDES something.
///
/// So this census counts a narrower, far higher-signal set: functions whose NAME declares they decide —
/// `verify_*`, `validate_*`, `check_*`, `prove_*`, `attest_*`, `audit_*`, `sample_*`, `refuse_*`,
/// `enforce_*`, and the `*_proof` / `*_valid` / `*_check` tails. A deciding function with no production
/// caller is a check the chain does not run, however complete and however well gated it is in tests.
/// That is the DA shape exactly, and it is the shape a "dead code" lint never reports, because these all
/// have callers — in `#[cfg(test)]`.
fn is_deciding_name(name: &str) -> bool {
    // ⭐ `accept_` EARNED ITS PLACE BY THE CALIBRATION FAILING. `solvency::accept_solvency` is the PSM
    // mint quorum's confidential gate — as deciding a function as exists in this tree — and the first
    // draft's head list did not cover it, so the census never saw it at all. The calibration named it
    // rather than the instrument silently omitting a whole naming convention. Widening the heads took
    // the census from 34 deciders to 47 and found no new holes, which is the answer you want from a
    // widening: more covered, same verdict.
    const HEADS: &[&str] = &[
        "verify_", "validate_", "check_", "prove_", "attest_", "audit_", "sample_", "refuse_",
        "enforce_", "accept_", "admit_", "authorize_", "reject_",
    ];
    const TAILS: &[&str] =
        &["_proof", "_verify", "_valid", "_check", "_attested", "_sampled", "_refused"];
    HEADS.iter().any(|h| name.starts_with(h)) || TAILS.iter().any(|t| name.ends_with(t))
}

/// Every deciding function declared in PRODUCTION, with the number of production call sites outside its
/// own declaration. Declarations are read from the filesystem, the same as the module census.
fn decider_census(files: &[(String, String)]) -> BTreeMap<String, usize> {
    let mut declared: Vec<String> = Vec::new();
    let mut bodies: Vec<String> = Vec::new();
    for (p, txt) in files {
        if is_test_file(p) {
            continue;
        }
        let prod = strip_comment_lines(&strip_test_spans(txt));
        for line in prod.lines() {
            let t = line.trim_start();
            let rest = t
                .strip_prefix("pub fn ")
                .or_else(|| t.strip_prefix("pub(crate) fn "))
                .or_else(|| t.strip_prefix("pub(super) fn "));
            if let Some(r) = rest {
                let name: String =
                    r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if !name.is_empty() && is_deciding_name(&name) && !declared.contains(&name) {
                    declared.push(name);
                }
            }
        }
        bodies.push(prod);
    }
    let mut out = BTreeMap::new();
    for name in declared {
        let mut n = 0usize;
        for body in &bodies {
            for line in body.lines() {
                let t = line.trim_start();
                // A DECLARATION is not a call, and neither is the doc line that names it.
                if t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ") || t.contains("fn ") {
                    if t.contains(&format!("fn {name}")) {
                        continue;
                    }
                }
                let mut from = 0usize;
                while let Some(k) = line[from..].find(&name) {
                    let at = from + k;
                    let before = line[..at].chars().next_back();
                    let after = line[at + name.len()..].chars().next();
                    let word = !matches!(before, Some(c) if c.is_alphanumeric() || c == '_');
                    // `f(` is a call; `f:` / `f,` / `f)` is a function VALUE passed as an argument —
                    // both are production uses. ⛔ A method reference reads as uncalled to a
                    // grep for `f(`, which is how a wired function gets filed dead.
                    if word && matches!(after, Some('(') | Some(':') | Some(',') | Some(')')) {
                        n += 1;
                    }
                    from = at + name.len();
                }
            }
        }
        out.insert(name, n);
    }
    out
}

/// ⛔ DECIDING FUNCTIONS THE CHAIN DOES NOT RUN — each with what production does INSTEAD.
///
/// ⭐⭐⭐ SHRINK-ONLY. A new deciding function with no production caller fails the gate, and one that
/// gets wired must be DELETED from this list. Nothing may be added without a reason that names the
/// production path that decides instead — "it is tested" is not one.
const DECIDERS_FILED_UNWIRED: &[(&str, &str)] = &[
    (
        "all_verify",
        "WALLET-SIDE PRE-SEND, not a consensus gate. `nf_sparse::SpendBundle::all_verify` re-checks a          wallet's own carries against the live root so it learns BEFORE it sends; the gate that decides          a spend is `SparseNfAcc::verify_unspent`, which every node runs per nullifier. Wiring this into          the node would re-verify the same copaths a second time and decide nothing new.",
    ),
    (
        "verify_solvency_if_present",
        "THE BLOCK-CARRIED SOLVENCY GATE, and no block carries a solvency carrier — `SolvencyProof`          reaches consensus only through the PSM mint quorum, where `psm::authorize_mint` DOES run          `accept_solvency` on every mint. HF38's entry point is ready for a block that carries one;          until a block does, this decides nothing. ⛔ Re-file the moment the block gains the field.",
    ),
    (
        "verify_bond_admit",
        "#75 brick 4 — the CONFIDENTIAL bond path. Production runs the CLEARTEXT one: `ValidatorSet::         admit`/`remove` maintain `total_bond`, which is the denominator of every ≥2/3 gate, and a          carried bonding tx is verified by `verify_carried_bond_tx` (a WHIR bond-validity carrier plus          a note-membership fold). So a bond IS proven — just not through the value-hiding commitment.          ⛔ That is a PRIVACY gap, not a funds gap: the bonded total is a cleartext u128 today.",
    ),
    (
        "verify_bond_reduce",
        "The unbond/slash half of the same #75 brick 4 confidential path. Production reduces through          `ValidatorSet::remove`/`slash` on the cleartext `total_bond`. Same standing: privacy, not funds.",
    ),
    (
        "verify_block_vdf",
        "⛔ THE PQ-VDF BLOCK CLOCK IS NOT IN THE HEADER AT ALL. Production references `vdf_clock` for          exactly one thing — the constant `VDF_STEPS_PER_BLOCK`, copied into `params::VDF_STEPS_DEFAULT`          — so no block carries a VDF output and nothing verifies one. Block timing rests on PoUW and the          DAA alone (Bitcoin's shape, so not a funds hole), and this is the purest DA-class seam in the          tree: a complete, tamper-gated primitive that the chain never asks.",
    ),
];

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// ⭐⭐⭐ RUN THIS ONE FIRST. Two drafts of this census were broken and BOTH printed a clean,
    /// plausible list of dead modules. The only thing that catches that is asserting the instrument
    /// finds callers for modules verified BY HAND to have them.
    #[test]
    fn the_seam_census_is_calibrated() {
        let files = source_files();
        assert!(files.len() > 50, "the walk found {} files — it is not reading the tree", files.len());
        let c = census(&files);
        let blind: Vec<&str> = CALIBRATION_WIRED
            .iter()
            .copied()
            .filter(|m| c.get(*m).copied().unwrap_or(0) == 0)
            .collect();
        assert!(
            blind.is_empty(),
            "⛔ THE SEAM CENSUS IS BROKEN — it reports these hand-verified WIRED modules as having no \
             production caller: {blind:?}. Every finding it produces is worthless until this passes. \
             Do NOT relax the calibration set to make it green: the two known ways to break this census \
             are counting only `m::` paths (missing `use`+bare-type) and truncating at the first \
             `#[cfg(test)]` (throwing away most of a 42k-line file)."
        );
    }

    /// ⭐ A NEW SUBSYSTEM CANNOT BE ADDED AND LEFT UNWIRED IN SILENCE. That is how `src/da.rs` sat with
    /// zero callers behind a dozen comments calling it the note store.
    #[test]
    fn every_declared_module_states_whether_production_calls_it() {
        let declared = declared_modules();
        let missing: Vec<&String> = declared
            .iter()
            .filter(|m| !SEAM_MANIFEST.iter().any(|(n, _)| *n == m.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ {} MODULE(S) DECLARED IN `lib.rs` WITH NO SEAM ENTRY: {missing:?}. Say whether \
             production calls it (`Seam::Wired`) or why it deliberately does not (`Seam::Unwired`). A \
             subsystem nobody calls is not an unfinished feature, it is a claim the code does not keep — \
             and every comment elsewhere that cites it is then describing something that never runs.",
            missing.len()
        );
        let stale: Vec<&str> = SEAM_MANIFEST
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !declared.iter().any(|m| m == n))
            .collect();
        assert!(stale.is_empty(), "seam entries for modules `lib.rs` no longer declares: {stale:?}");
    }

    /// ⛔⛔⛔ THE GATE. A module declared WIRED that has lost its last production caller is dead code
    /// wearing a live name, and every comment that cites it is now false.
    #[test]
    fn every_wired_seam_has_a_production_caller() {
        let files = source_files();
        let c = census(&files);
        let dead: Vec<(&str, usize)> = SEAM_MANIFEST
            .iter()
            .filter(|(_, s)| *s == Seam::Wired)
            .map(|(n, _)| (*n, c.get(*n).copied().unwrap_or(0)))
            .filter(|(_, k)| *k == 0)
            .collect();
        assert!(
            dead.is_empty(),
            "⛔ MODULE(S) DECLARED WIRED WITH ZERO PRODUCTION CALLERS: {dead:?}. Either something that \
             used to call them stopped — in which case find out what the chain now does instead — or \
             they were never wired and the entry is wrong. Do not flip the entry to `Unwired` without \
             naming the reason and recording it in the kill list."
        );
    }

    /// ⭐ AND THE MANIFEST MUST NOT GO STALE IN THE GOOD DIRECTION EITHER. A seam declared unwired that
    /// has since been wired is a finding too: its reason is now obsolete, and the kill-list entry that
    /// tracks it should be closed rather than left describing a hole that no longer exists.
    #[test]
    fn every_unwired_seam_is_still_unwired_and_says_why() {
        let files = source_files();
        let c = census(&files);
        let mut now_wired: Vec<(&str, usize)> = Vec::new();
        for (n, s) in SEAM_MANIFEST {
            if let Seam::Unwired(reason) = s {
                assert!(
                    reason.len() > 30,
                    "`{n}` is declared unwired with no real reason — name what the chain does instead"
                );
                let k = c.get(*n).copied().unwrap_or(0);
                if k > 0 {
                    now_wired.push((*n, k));
                }
            }
        }
        assert!(
            now_wired.is_empty(),
            "⭐ SEAM(S) DECLARED UNWIRED ARE NOW CALLED FROM PRODUCTION: {now_wired:?}. Good news — \
             flip them to `Seam::Wired` and close their kill-list entry, so the manifest stops \
             describing a hole that has been filled."
        );
    }

    /// ⭐⭐⭐ A CROSS-CRATE CLAIM MUST BE FINDABLE, OR IT IS A STORY.
    ///
    /// ⛔⛔⛔ THE BLIND SPOT THIS CLOSES. The census reads `<node>/src` and nothing else, so a subsystem
    /// whose only consumer lives in ANOTHER crate of this workspace reads as dead. `ble_frame` sat filed
    /// as `Unwired` with the reason *"no node path speaks it"* — true of this crate, and the wrong
    /// conclusion: `BleCellPump` is constructed over `serve::ble_bridge()` and driven in BOTH directions
    /// by `monerousd-wallet-v2/src-tauri/src/moneropay_ble.rs`. It was on the list of gaps to CLOSE, and
    /// closing a gap that is not there is how a working transport gets deleted. Same shape as the
    /// split-impl near-miss that almost took GHOSTDAG, on a different axis.
    ///
    /// So `WiredCrossCrate` is a CHECKED claim, not a label: the consumer crate is read from disk and
    /// must actually name the module. A crate that has moved or been renamed fails here rather than
    /// letting an unverifiable claim stand.
    #[test]
    fn every_cross_crate_claim_names_a_consumer_that_really_calls_it() {
        // The workspace siblings a node subsystem may legitimately be consumed by.
        let roots = [
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .map(|p| p.join("monerousd-wallet-v2").join("src-tauri").join("src")),
        ];
        let mut consumer_src = String::new();
        let mut read_any = false;
        for r in roots.into_iter().flatten() {
            let mut files = Vec::new();
            fn walk(dir: &PathBuf, out: &mut Vec<(String, String)>) {
                let Ok(rd) = std::fs::read_dir(dir) else { return };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else if p.extension().is_some_and(|x| x == "rs")
                        && !p.to_string_lossy().contains(".rs.")
                    {
                        if let Ok(t) = std::fs::read_to_string(&p) {
                            out.push((p.to_string_lossy().to_string(), t));
                        }
                    }
                }
            }
            walk(&r, &mut files);
            if !files.is_empty() {
                read_any = true;
            }
            for (_, t) in files {
                consumer_src.push_str(&t);
            }
        }
        let claims: Vec<&str> = SEAM_MANIFEST
            .iter()
            .filter(|(_, s)| matches!(s, Seam::WiredCrossCrate))
            .map(|(n, _)| *n)
            .collect();
        if claims.is_empty() {
            return; // nothing claims cross-crate wiring; nothing to verify
        }
        assert!(
            read_any,
            "⛔ THE CONSUMER CRATE COULD NOT BE READ, yet {claims:?} claim it calls them. An              unverifiable claim is worse than an `Unwired` entry: it stops anyone looking. Point this              test at the crate that really holds the consumer, or downgrade the claim."
        );
        let mut unfounded = Vec::new();
        for n in &claims {
            // The consumer must name the module — by path (`usdmd_node::ble_frame`) or by `use`.
            if !consumer_src.contains(&format!("::{n}")) && !consumer_src.contains(&format!("{n}::")) {
                unfounded.push(*n);
            }
        }
        assert!(
            unfounded.is_empty(),
            "⛔⛔⛔ A SEAM CLAIMS A CROSS-CRATE CONSUMER THAT DOES NOT NAME IT: {unfounded:?}. Either the              consumer moved (find where it went) or the claim was wrong and the module really is dead."
        );
    }

    /// ⭐⭐⭐ THE SECOND INSTRUMENT — AND THE ONE THAT CANNOT HAVE A BLIND SPOT.
    ///
    /// Every version of the static census has been wrong in a way that still printed a clean list:
    /// path-only counting, truncate-at-first-`#[cfg(test)]`, and split `impl` blocks. Three blind spots
    /// in one instrument is the signal that **a reading is not a verdict**. So this test does not read
    /// the source at all. It DELETES the module declaration and asks the COMPILER:
    ///
    /// > does production still build without you?
    ///
    /// A module that is genuinely uncalled compiles out with zero production errors. One that is reached
    /// by any mechanism whatever — a path, a bare type, a trait, a split `impl`, a macro, a re-export —
    /// breaks the build, because the compiler resolves what a grep cannot.
    ///
    /// ⛔ SLOW BY NATURE (one `cargo check` per module), so it is `#[ignore]`d and run on demand:
    /// ```text
    /// cargo test --release --lib harness::seam::the_census_findings_survive_a_removal_probe \
    ///     -- --ignored --nocapture
    /// ```
    /// Run it whenever the manifest changes, and whenever a finding is about to be ACTED on — deleting
    /// a module, or filing it as a hole. MEASURED 2026-09-13: `ghostdag` 4 errors (wired, the control);
    /// all 7 declared-unwired modules 0 errors (confirmed dead in production).
    #[test]
    #[ignore = "runs one cargo check per module; the fast census is the CI gate"]
    fn the_census_findings_survive_a_removal_probe() {
        /// Restores `lib.rs` even if an assertion unwinds. ⛔ A probe that mutates the tree and panics
        /// leaves the crate uncompilable — the guard is not optional.
        struct Restore {
            path: PathBuf,
            original: String,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = fs::write(&self.path, &self.original);
            }
        }

        // the module is cut where it is declared: `lib.rs` for the node's own, `ledger_lib.rs` for the ledger crate's (stage B)
        let roots = [src_root().join("lib.rs"), src_root().join("ledger_lib.rs")];
        let originals: Vec<String> = roots.iter().map(|p| fs::read_to_string(p).expect("crate root")).collect();
        let _restore: Vec<Restore> =
            roots.iter().zip(&originals).map(|(p, o)| Restore { path: p.clone(), original: o.clone() }).collect();

        // A SEPARATE target dir: this runs inside a `cargo test`, and sharing one would block on the
        // build lock held by our own harness.
        let target = std::env::temp_dir().join("usdmd-seam-removal-probe");

        let probe = |module: &str| -> usize {
            let cut = format!("pub mod {module};");
            let at = originals.iter().position(|o| o.contains(&cut));
            let Some(at) = at else { panic!("`{module}` is not declared in lib.rs or ledger_lib.rs as `{cut}`") };
            let (lib, original) = (&roots[at], &originals[at]);
            fs::write(lib, original.replace(&cut, &format!("// SEAM-REMOVAL-PROBE {cut}")))
                .expect("write probe");
            let out = std::process::Command::new(env!("CARGO"))
                .args(["check", "--release", "--lib", "--message-format=short"])
                .current_dir(src_root().parent().expect("crate root"))
                .env("CARGO_TARGET_DIR", &target)
                .output()
                .expect("cargo check");
            fs::write(lib, original).expect("restore");
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .filter(|l| l.contains(": error[") || l.contains(": error:"))
                .count()
        };

        // ⭐ CALIBRATION FIRST, ALWAYS. A probe that reports "0 errors" for everything — a cargo that
        // cannot run, a target dir it cannot write — would certify every module dead. The control must
        // BREAK before any finding it produces is worth reading. `ghostdag` is the right control: it is
        // reachable ONLY as `impl Dag`, the exact shape the static census could not see.
        let control = probe("ghostdag");
        assert!(
            control > 0,
            "⛔ THE REMOVAL PROBE IS BLIND — deleting `ghostdag` (reached as `impl Dag` and called by              `dag.rs` on every block) produced NO production errors. Either cargo did not run or it              did not compile production code. Every 0 it reports is meaningless until this fails."
        );

        let mut alive: Vec<(&str, usize)> = Vec::new();
        for (n, s) in SEAM_MANIFEST {
            if matches!(s, Seam::Unwired(_)) {
                let errs = probe(n);
                eprintln!("[seam-probe] {n}: production errors after removal = {errs}");
                if errs > 0 {
                    alive.push((*n, errs));
                }
            }
        }
        assert!(
            alive.is_empty(),
            "⭐ THESE MODULES ARE DECLARED UNWIRED BUT PRODUCTION DOES NOT COMPILE WITHOUT THEM:              {alive:?}. The compiler is right and the manifest is wrong — they are reached by some              mechanism the static census cannot see (this is how `ghostdag`, a split `impl Dag`, was              nearly deleted). Find the mechanism, flip the entry to `Seam::Wired`, and teach the census              about it so the next one is caught statically."
        );
    }

    /// ⭐⭐⭐ CALIBRATION FOR THE DECIDER CENSUS — hand-verified WIRED deciders must show callers.
    ///
    /// Same law as the module census: an instrument that cannot find the callers it is supposed to find
    /// will certify a clean sweep over a tree full of holes. `verify_chunk` / `inclusion_proof` /
    /// `sample_indices` are in here deliberately — they ARE the DA gap, now closed, so they are the
    /// canary for the exact failure this census exists to catch.
    #[test]
    fn the_decider_census_is_calibrated() {
        const KNOWN_WIRED: &[&str] = &[
            "verify_chunk",         // §AM — the DA sampling triple, the gap that prompted this census
            "inclusion_proof",      //  …
            "sample_indices",       //  …
            "verify_block_pow",     // #73 consensus PoUW verify, run by `preverify_block`
            "accept_solvency",      // the PSM mint quorum's confidential solvency gate
            "verify_unspent",       // the double-spend gate every node runs per nullifier
        ];
        let files = source_files();
        let c = decider_census(&files);

        // ⛔⛔ TWO DIFFERENT FAILURES WEAR ONE NUMBER, AND CONFLATING THEM SENDS YOU TO THE WRONG PLACE.
        // "counted, zero callers" means the COUNTER is broken. "not in the census at all" means the
        // NAME LIST is — the function is not being looked at, which is far worse and reads identically
        // as a zero. MEASURED: the first draft reported `accept_solvency` blind, and the cause was that
        // `accept_` was not a deciding prefix, so a whole naming convention was invisible.
        let unseen: Vec<&str> =
            KNOWN_WIRED.iter().copied().filter(|f| !c.contains_key(*f)).collect();
        assert!(
            unseen.is_empty(),
            "⛔⛔ THE DECIDER CENSUS IS NOT LOOKING AT THESE AT ALL: {unseen:?}. They are hand-verified \
             deciding functions and the census has no entry for them — so its verdict on them is not \
             'wired' or 'unwired', it is SILENCE. Either the name does not match `is_deciding_name` \
             (widen the head/tail lists — a naming convention nobody modelled is a blind census) or it \
             is not declared `pub fn` in production. Fix the instrument, never the calibration set."
        );

        let blind: Vec<&str> = KNOWN_WIRED
            .iter()
            .copied()
            .filter(|f| c.get(*f).copied().unwrap_or(0) == 0)
            .collect();
        assert!(
            blind.is_empty(),
            "⛔ THE DECIDER CENSUS CANNOT COUNT — it sees these hand-verified WIRED deciding functions \
             but finds no production caller: {blind:?}. Every finding it produces is worthless until \
             this passes."
        );
    }

    /// ⛔⛔⛔ THE GATE THE DA LAYER NEEDED AND DID NOT HAVE.
    ///
    /// A function whose name says it VERIFIES, PROVES, CHECKS, SAMPLES or AUDITS something, and which
    /// nothing in production calls, is a check the chain does not run. It compiles, it has tamper tests,
    /// it is cited in comments as load-bearing — and it decides nothing. `da::verify_chunk` sat in
    /// exactly that state while twelve comments called `da.rs` the note store.
    ///
    /// SHRINK-ONLY: a NEW unwired decider fails here, and one that gets wired must be deleted from
    /// `DECIDERS_FILED_UNWIRED`. Neither direction may go stale in silence.
    #[test]
    fn every_deciding_function_is_either_called_by_production_or_filed_with_what_decides_instead() {
        let files = source_files();
        let c = decider_census(&files);

        let undeclared: Vec<&String> = c
            .iter()
            .filter(|(_, k)| **k == 0)
            .map(|(n, _)| n)
            .filter(|n| !DECIDERS_FILED_UNWIRED.iter().any(|(f, _)| *f == n.as_str()))
            .collect();
        assert!(
            undeclared.is_empty(),
            "⛔⛔⛔ DECIDING FUNCTION(S) THE CHAIN DOES NOT RUN: {undeclared:?}. Each names itself a \
             verify/prove/check/sample and has ZERO production call sites — it is gated in tests and \
             wired to nothing, which is precisely how `da::{{verify_chunk, inclusion_proof, \
             sample_indices}} sat unused while a producer could commit a note root and withhold the \
             bytes forever (§AM). WIRE IT, or add it to `DECIDERS_FILED_UNWIRED` with the production \
             path that decides instead. ⛔ \"it is tested\" is not a reason."
        );

        let now_wired: Vec<(&str, usize)> = DECIDERS_FILED_UNWIRED
            .iter()
            .filter_map(|(f, _)| {
                let k = c.get(*f).copied().unwrap_or(0);
                if k > 0 { Some((*f, k)) } else { None }
            })
            .collect();
        assert!(
            now_wired.is_empty(),
            "⭐ FILED-UNWIRED DECIDER(S) ARE NOW CALLED FROM PRODUCTION: {now_wired:?}. Good news — \
             DELETE them from `DECIDERS_FILED_UNWIRED`. The list is SHRINK-ONLY; leaving a closed hole \
             on it is how a stale filing hides the next real one."
        );

        for (f, reason) in DECIDERS_FILED_UNWIRED {
            assert!(
                reason.len() > 60,
                "`{f}` is filed unwired without naming what production runs instead — that reason is \
                 the whole point of the filing"
            );
        }
    }

    /// ⛔⛔⛔ THE GATE FOR THE EXACT SHAPE THE DA LAYER WORE — and it is CALIBRATED ON THAT CASE.
    ///
    /// A module the rest of the tree documents as live, that production never calls, is the hole §AM was.
    /// Being unwired is not by itself a defect; being unwired while five other files' doc comments point
    /// at you eighteen times is, because every one of those citations tells a reviewer the mechanism runs.
    ///
    /// ⭐⭐⭐ THE CALIBRATION IS THE HISTORICAL CASE ITSELF. `da` still measures above the threshold, so
    /// this test proves the rule WOULD have fired on the gap that prompted it. A "simplification" of the
    /// counter that stops finding citations drops `da` below the line and fails here — which is the only
    /// thing that keeps a passing run meaningful ([[reference_refutation_before_green]]).
    #[test]
    fn a_seam_the_tree_documents_as_load_bearing_may_not_be_called_by_nothing_in_silence() {
        let files = source_files();

        let da = doc_citations("da", &files);
        assert!(
            da >= CITED_AS_LOAD_BEARING,
            "⛔ THE CITATION COUNTER IS BLIND — `da`, the module whose 18 doc citations across five files \
             sat above ZERO production callers until §AM, now measures {da}, below the {CITED_AS_LOAD_BEARING} \
             threshold. Either the counter stopped finding code references or it is counting the wrong \
             thing. Until this holds, a green run here proves nothing: the rule is not demonstrated to \
             fire on the one case we KNOW it had to catch."
        );

        let c = census(&files);
        let mut unacknowledged: Vec<(&str, usize)> = Vec::new();
        for (n, seam) in SEAM_MANIFEST {
            let Seam::Unwired(reason) = seam else { continue };
            if c.get(*n).copied().unwrap_or(0) > 0 {
                continue; // the staleness test owns this case
            }
            let cites = doc_citations(n, &files);
            if cites >= CITED_AS_LOAD_BEARING && !reason.contains(CITED_MARKER) {
                unacknowledged.push((*n, cites));
            }
        }
        assert!(
            unacknowledged.is_empty(),
            "⛔⛔⛔ SEAM(S) THE TREE DOCUMENTS AS LOAD-BEARING AND NOTHING CALLS: {unacknowledged:?} \
             (module, production doc citations in OTHER files). This is the `da.rs` shape exactly — a \
             complete primitive cited as the mechanism while a producer could commit a note root and \
             withhold the bytes forever (§AM). WIRE IT. If it genuinely must stay unwired, say so in its \
             `Seam::Unwired` reason behind the marker `{CITED_MARKER}`, naming what those citations are \
             actually describing — so the next reader is not told by {CITED_AS_LOAD_BEARING}+ comments \
             that a dead mechanism is live."
        );
    }

    /// The census, printed. Not an assertion — a standing report, so the shape of the tree's wiring is
    /// visible on every run rather than only when something breaks.
    #[test]
    fn report_the_seam_census() {
        let files = source_files();
        let c = census(&files);
        let unwired: Vec<(&String, &usize)> = c.iter().filter(|(_, k)| **k == 0).collect();
        eprintln!(
            "[seam] {} module(s) declared, {} with ZERO production callers: {:?}",
            c.len(),
            unwired.len(),
            unwired.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>()
        );
        let d = decider_census(&files);
        let dead: Vec<&str> = d.iter().filter(|(_, k)| **k == 0).map(|(n, _)| n.as_str()).collect();
        eprintln!(
            "[seam] {} deciding fn(s) in production, {} with ZERO production callers: {:?}",
            d.len(),
            dead.len(),
            dead
        );
        let cites: Vec<(&str, usize)> = SEAM_MANIFEST
            .iter()
            .filter(|(n, s)| matches!(s, Seam::Unwired(_)) && c.get(*n).copied().unwrap_or(0) == 0)
            .map(|(n, _)| (*n, doc_citations(n, &files)))
            .collect();
        eprintln!(
            "[seam] unwired seams by DOC CITATIONS (cited-as-load-bearing is the `da` shape, threshold {CITED_AS_LOAD_BEARING}): {cites:?}"
        );
    }
}

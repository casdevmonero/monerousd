// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE AUTHORITY MANIFEST, AXIS 2 — THE STRUCTS THAT ARE NOT `Node`.**
//!
//! §J of the kill list names the gap this file closes, in its own words: *"the manifest covers `Node`'s
//! 142 fields ONLY. `PegLedger`, `OrderBook`, `Directory`, `ValidatorSet`, `Mempool` and the wallet each
//! hold their own state with no manifest at all."* Driving `Node`'s backlog to zero completes one axis
//! of one defect class for one struct. This is the second axis, for the three structs where the class
//! costs a user money most directly.
//!
//! | struct | the funds question |
//! |---|---|
//! | `OrderBook` | the 2026-09-03 double payout: a fill's burn was LOCAL, so the maker's order stayed live on the other node and the same lot paid out twice — with both nodes individually correct |
//! | `Directory` | **`#64 Pay @username` SENDS MONEY TO WHOEVER THE DIRECTORY RESOLVES.** A directory that is not a function of the chain resolves a DIFFERENT owner on a joining node, so the payment goes to the wrong person |
//! | `ValidatorSet` | it decides every ≥2/3 threshold in the peg, so a node with a different set weighs mint and redeem authority differently from the mesh |
//!
//! ── WHAT THIS LANE PROVES, AND WHAT IT DOES NOT ─────────────────────────────────────────────────
//! ⛔ STATED BEFORE ANY NUMBER IS CITED, because a coverage claim nobody bounded is how "reads as
//! covered" happens in the first place.
//!
//! **What it proves.** Every field of the three structs is classified; a field added to any of them
//! without a ruling FAILS the build; and every field declared `ChainDerived` here has a COMPARISON in
//! this file that has been made to go red on a constructed violation and shown silent on an honest
//! instance. The comparison is the chain-replay shape: two instances that have taken in the same
//! chain-visible history must agree, and the one holding what the chain did not produce is named.
//!
//! **What it does not prove.** These comparisons do not yet ride `Sim::cold_peer_verdict` — that file
//! is held by another author today — so a CAMPAIGN does not run them. Until they are wired there, this
//! lane proves the comparisons EXIST and CAN FIRE; it does not prove a live mesh is checked by them.
//!
//! ── ⭐⭐⭐ THE MEASUREMENT THAT MOTIVATES ALL OF IT ─────────────────────────────────────────────
//! `cold_peer_verdict` already reads these three structs. Read what it actually asks them
//! (`src/consensus_scenarios.rs:1071`):
//!
//! | struct | what the chain-only replay compares TODAY | what that read cannot see |
//! |---|---|---|
//! | `OrderBook` | `order_book_len_for_audit()` — the COUNT | two nodes each holding ONE order that is a DIFFERENT one. E-7 is an IDENTITY question: *whose lot is still live* |
//! | `ValidatorSet` | `validators().len()` — the SIZE | every WEIGHT. The ≥2/3 gate divides by `total_bond`, and two sets of equal size can carry entirely different bonded weight |
//! | `Directory` | `dir_acc()` — the ACCUMULATOR | the RESOLUTION MAPS. `apply_entry` moves the maps; `fold_applied` moves the accumulator; they are two separate calls |
//!
//! Each row is refuted below as a pair: a state this file's comparison reports, and an assertion that
//! the coarse read is EQUAL on that same state. A count, a size, and a digest of something else are not
//! coverage of the value a user's money depends on.
//!
//! ── THE RATCHETS ───────────────────────────────────────────────────────────────────────────────
//! Same three shrink-only properties as [`super::authority`], applied per struct:
//!   1. **NO NEW GAP** — every field of the struct must appear in its manifest, checked by PARSING the
//!      struct out of its own source file (the source-absence technique: a missing classification has
//!      no runtime handle and can only be caught by reading the code);
//!   2. **THE UNDECIDED BACKLOG ONLY SHRINKS** — `MAX_UNCLASSIFIED_*`, a measurement, never a choice;
//!   3. **THE DECLARED-BUT-UNCOMPARED SURFACE ONLY SHRINKS** — `MAX_UNCOMPARED_*`. Declaring a field
//!      `ChainDerived` is a CLAIM; a claim nothing compares is WORSE than an undecided field, because
//!      it reads as covered.
//!
//! ⛔ A CLASSIFICATION IS A FUNDS-SAFETY CLAIM. Where the answer is genuinely contested the field stays
//! `Unclassified` with the reason written down. There is exactly one such field here and it is named.

use super::authority::Authority;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// ORDER BOOK — src/order_book.rs
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Every field of `struct OrderBook`, with who decides it.
///
/// ⚠️ THE ONE FIELD IS CONTESTED IN THE SOURCE, AND THE RULING IS ARGUED RATHER THAN ASSUMED.
/// `order_book.rs` opens with *"⛔⛔⛔ ZERO PER-ORDER CHAIN STATE. Nothing here is persisted to the
/// snapshot, folded into an accumulator, or bound into a block id."* That is true of an order's
/// ARRIVAL: an offer reaches a book by gossip, and an offer nobody has accepted has no business on a
/// ledger.
///
/// It is NOT true of an order's DEPARTURE. A resting order is retired by a FILL or a CANCEL, and both
/// are chain events — a burn of the resting nullifier. E-7 is precisely that asymmetry: the burn was
/// applied on the node that saw the fill and nowhere else, so the maker's lot stayed live elsewhere and
/// the same lot paid out twice. `harness::fuzz::authority` already rules `Node::order_book`
/// `ChainDerived` and `Sim::cold_peer_verdict` already compares it, so `ChainDerived` is also the
/// ruling that keeps the two manifests from contradicting each other.
pub const ORDER_BOOK_MANIFEST: &[(&str, Authority)] = &[("orders", Authority::ChainDerived)];

/// The `OrderBook` fields this file COMPARES against a chain-replay instance.
pub const ORDER_BOOK_COMPARED: &[&str] = &["orders"];

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 by parsing `pub struct OrderBook` out of
/// `src/order_book.rs`: **1 field · 1 chain-derived · 0 local cache · 0 undecided.**
/// **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCLASSIFIED_ORDER_BOOK: usize = 0;

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 from this file:
///     1 field declared `ChainDerived` − 1 named in `ORDER_BOOK_COMPARED` = **0 not yet compared.**
/// Written down rather than computed, so that ADDING a chain-derived field cannot silently raise the
/// backlog: a new declaration pushes the live count past this ceiling and fails.
/// **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCOMPARED_ORDER_BOOK: usize = 0;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// DIRECTORY — src/directory.rs
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Every field of `struct Directory`, with who decides it.
///
/// The three maps are the sharpest fields in this whole file: `#64 Pay @username` resolves through
/// `names`, a Letter joiner seals a join request to `groups`' `owner_addr`, and `profiles` carries
/// `fee_micro` — a PRICE in micro-USDm a sender pays to get a message accepted. Each is a deterministic
/// fold of the block-carried `Block::dir_set` (the module header says so, and `Node::apply_dir_set`
/// re-verifies every ML-DSA signature on every node), so `ChainDerived` is the claim the code already
/// makes. Nothing was comparing them.
pub const DIRECTORY_MANIFEST: &[(&str, Authority)] = &[
    ("names", Authority::ChainDerived),
    ("groups", Authority::ChainDerived),
    ("profiles", Authority::ChainDerived),
    // Spec §12.6 (lane goods; declared 2026-11-12 by the lane that added them, after the manifest pin read them missing):
    // the collections and the assets' records, written only by the folds of a paid collection entry, a creation, a mint
    // and the minting object's supply, journaled with their step and refilled from the certified sequence; and their two
    // indexes (an asset by its notes' tag, collections in the order the chain applied them). Compared below.
    ("collections", Authority::ChainDerived),
    ("assets", Authority::ChainDerived),
    ("asset_tags", Authority::ChainDerived),
    ("collection_order", Authority::ChainDerived),
    ("acc", Authority::ChainDerived),
    // The PICTURES by digest, how many records name each, and the ones this node still lacks: a store of self-checking
    // bytes, NOT part of the certified directory word (the records name pictures by digest); a node missing one asks any
    // peer for it and checks it by hashing. Which nodes hold which pictures is a holding policy, never consensus.
    ("pics", Authority::LocalCache),
    ("pic_refs", Authority::LocalCache),
    ("pics_owed", Authority::LocalCache),
    // ⛔⛔ THE ONE HONEST "NOT YET" IN THIS FILE, and the reason is a real contradiction in the code
    // rather than a shortage of effort:
    //   * `log` is SERVED — `log_page` is what the refill door hands a jumped peer as the certified
    //     sequence, and every entry it serves is re-applied through the full apply gate on the
    //     receiver. A wrong log therefore misdirects a joiner's payments, which is authority.
    //   * `log` is ALSO documented to legitimately DIFFER between two honest nodes. `reset_for_refill`
    //     exists because *"a jumped node's log has GAPS (it missed the spans it leapt), and the fold is
    //     order-sensitive — a gapped log can never re-fold to the certified acc."*
    // So its authority depends on a lifecycle phase: gapped is legal before a refill and a defect after
    // one. `ChainDerived` would make every jumped node a finding; `LocalCache` would say a registry
    // served to peers as certified is this node's own business. Both are wrong, and a wrong ruling is
    // worse than an honest "not yet" — so it is counted, capped, and left undecided.
    ("log", Authority::Unclassified),
    // Where THIS node's registry file lives. Serde-skipped, `None` on test nodes. Node-local by
    // construction and must never be compared or served — the same ruling `authority.rs` gives
    // `Node::persist_path`.
    ("persist_path", Authority::LocalCache),
];

/// The `Directory` fields this file COMPARES against a chain-replay instance.
///
/// ⭐ `acc` is the one field `Sim::cold_peer_verdict` already reads (`dir_acc()`). It is listed here
/// because this file compares it too, and because the refutation for `names` PROVES that comparing
/// `acc` alone is not coverage of the maps.
pub const DIRECTORY_COMPARED: &[&str] = &["names", "groups", "profiles", "collections", "assets", "asset_tags", "collection_order", "acc"];

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 by parsing `pub struct Directory` out of
/// `src/directory.rs`: **6 fields · 4 chain-derived · 1 local cache · 1 undecided (`log`).**
/// Lowering it is the work: rule on `log` — which requires deciding whether a gapped log is legal state
/// or a defect — then drop this number. **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCLASSIFIED_DIRECTORY: usize = 1;

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 from this file:
///     4 fields declared `ChainDerived` − 4 named in `DIRECTORY_COMPARED` = **0 not yet compared.**
/// **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCOMPARED_DIRECTORY: usize = 0;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// VALIDATOR SET — src/validator.rs
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Every field of `struct ValidatorSet`, with who decides it.
///
/// ⛔ `custody` IS THE ONE TO READ TWICE. `bonded_custody()` is the LIVE bonded set's key-aggregate,
/// and `Node::reserve_addresses` derives the BTC and XMR **deposit addresses** from it — the addresses
/// `src/rpc_http.rs:3337` serves to a user who is about to send real coin. Two nodes with different
/// custody sets hand that user DIFFERENT addresses, and at most one of them is controlled by the
/// quorum. So every node must reach the same value: the claim `ChainDerived` makes.
///
/// ⛔⛔ MEASURED 2026-09-09, AND IT IS A FINDING RATHER THAN A CLASSIFICATION PROBLEM: the chain does
/// not carry custody today. A `Block::bond_set` entry is *"validator_id 32 B + bond_amount 8 B + the
/// locked output0 blob"* (`src/block.rs:510`), and `grep -rn "secp33\|ed32" src/node.rs` returns only
/// `register_validator_custody` itself. Every non-test caller of it — `src/serve.rs:279,293` and
/// `src/main.rs:286,302` — seeds it from `bridge::charter_members_from_env()` or
/// `bridge::node_own_bridge_custody()` at STARTUP, from the local environment, with no block anywhere.
/// That is the `POST /register_wrapped_asset` shape (kill-list item 5) on the surface deciding where a
/// user's real BTC and XMR land. The field stays `ChainDerived` because that is what it must BE for the
/// reserve address to be agreed at all; the divergence is the defect, exactly as the collateral ratio
/// is under item 5.
pub const VALIDATOR_SET_MANIFEST: &[(&str, Authority)] = &[
    ("bonds", Authority::ChainDerived),
    ("custody", Authority::ChainDerived),
    ("total_bond", Authority::ChainDerived),
    // Every slash writes `bonds`, `total_bond` and `slashed` through the ONE shared slash function, at the bond step, from a
    // block-carried evidence object: `Class::Equivocation`, `Class::ReserveTheft`, and (§BR-9a, 2026-10-29)
    // `Class::EpochKeyFraud` — an epoch-key dealer convicted by t of its own committed shares rebuilding another public part.
    // Each is compared here (`VALIDATOR_SET_COMPARED`), so a slash applied on one node and not its peer fires the census.
    ("slashed", Authority::ChainDerived),
    // A conservation figure, not an instrument: these units LEFT the bonded weight forever, and it
    // rides `export_state`/`import_state` into the snapshot as value-bearing state. Two nodes that
    // disagree about how much bond was burned disagree about supply that moved, which the
    // local-decides cardinal puts on the chain by definition.
    ("slashed_bond_burned", Authority::ChainDerived),
    ("bond_commit", Authority::ChainDerived),
    // Each bonded custodian's ML-KEM encapsulation key, registered from its SIGNED seat header at
    // `apply_bond_set` on every node — chain-derived exactly like `custody`, and carried by the
    // certified DSYNC state (`validator_kem_eks`, bound into `sync_binding`).
    ("kem_eks", Authority::ChainDerived),
    // ⭐ SATOSHI §6 — the FINALITY seats (a USDm bond or a free membership seat) and their sum. Applied from block-carried
    // bonds on every node, carried by the snapshot and the certified DSYNC state (`finality_validators`, bound into
    // `sync_binding`): chain-derived exactly like `bonds`. A vote's finality weight is its custody seat PLUS its finality
    // seat, so two nodes that disagree here disagree about whether a block is final.
    ("finality_bonds", Authority::ChainDerived),
    // ⭐ G2b (2026-10-22) — the view at a height: each seat kind's activation height (the fold's chain-block landing height
    // plus FINALITY_SEAT_ACTIVATION_DELAY) and the departed rows an exit leaves; written only by the fold's seat / exit
    // doors, carried by the snapshot and the certified DSYNC state (bound into `sync_binding`): chain-derived like `bonds`.
    ("bond_active_from", Authority::ChainDerived),
    ("finality_active_from", Authority::ChainDerived),
    ("departed_bond", Authority::ChainDerived),
    ("departed_finality", Authority::ChainDerived),
    ("total_finality", Authority::ChainDerived),
    // ⭐ §BR-3 17.3 / 17.6 (classified 2026-10-29, lane defi — the fields landed with lanes funds-brb2/3 unclassified): each
    // id's delegated SAT word and its own-weight bonders' yield `(index last settled, accrued)`. Written only by the fold's
    // delegation, seat, re-bond, unbond, slash and claim doors; carried by the snapshot (`seat_words`) and the certified
    // state. A party with another delegated word re-bonds or pays an Undelegate its peers refuse; another yield word pays a
    // BondYieldClaim its peers refuse.
    ("delegated", Authority::ChainDerived),
    ("own_yield", Authority::ChainDerived),
];

/// The `ValidatorSet` fields this file COMPARES against a chain-replay instance.
///
/// ⭐ The comparison reads them through `export_state()` — the node snapshot's OWN deterministic
/// export, sorted by id — plus `total_bond()`. Using the real export rather than a bespoke reader means
/// the comparison cannot drift from what a restart actually carries.
pub const VALIDATOR_SET_COMPARED: &[&str] = &[
    "bonds",
    "total_bond",
    "slashed",
    "slashed_bond_burned",
    "bond_commit",
    "custody",
    "kem_eks",
    // SATOSHI §6: added with their manifest rows (2026-10-05), each refuted below.
    "finality_bonds",
    "total_finality",
    // G2b (2026-10-22): the view at a height, added with their manifest rows, refuted below.
    "bond_active_from",
    "finality_active_from",
    "departed_bond",
    "departed_finality",
    // §BR-3 17.3 / 17.6: added with their manifest rows (2026-10-29), compared through `seat_words()`, refuted below.
    "delegated",
    "own_yield",
];

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 by parsing `pub struct ValidatorSet` out of
/// `src/validator.rs`: **7 fields · 7 chain-derived · 0 local cache · 0 undecided** (re-measured
/// 2026-09-17 after `kem_eks` joined the set beside `custody`; 2026-10-05: **9 · 9 · 0 · 0** after SATOSHI's finality
/// seats `finality_bonds` + `total_finality`).
/// **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCLASSIFIED_VALIDATOR_SET: usize = 0;

/// ⛔ NOT A TUNED NUMBER — A MEASUREMENT taken 2026-09-09 from this file:
///     7 fields declared `ChainDerived` − 7 named in `VALIDATOR_SET_COMPARED` = **0 not yet compared.**
///     (2026-10-05: 9 − 9 = **0** with the finality seats; 2026-10-22: 13 − 13 = **0** with G2b's activation view.)
/// **MAY BE LOWERED, NEVER RAISED.**
pub const MAX_UNCOMPARED_VALIDATOR_SET: usize = 0;

#[cfg(all(test, feature = "pins-harness"))]
mod manifest {
    use super::*;

    /// Parse the field names of one struct straight out of its source file.
    ///
    /// ⭐ SOURCE-ABSENCE TECHNIQUE, the same method as `authority::manifest::node_fields`, parameterised
    /// by source + header so three structs share one parse. Some defects are an ABSENCE — a missing
    /// bound, a missing classification — and an absence has no runtime handle to observe. Reading the
    /// code is how an absence becomes assertable at all.
    fn struct_fields(src: &str, header: &str) -> Vec<String> {
        let start = src
            .find(header)
            .expect("the struct header this manifest names is present in its own source file");
        let mut depth = 0usize;
        let mut end = start;
        for (k, ch) in src[start..].char_indices() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = start + k;
                    break;
                }
            }
        }
        let mut out = Vec::new();
        for line in src[start..end].lines() {
            let t = line.trim_start();
            // ⛔ WHY THIS TEST NARROWS TO FOUR-SPACE NON-COMMENT LINES, AND WHY IT CANNOT BE DELETED.
            //
            // WHAT PRODUCES the other lines: rustc source text. Between two field declarations a struct
            // body carries doc comments, attributes, and deeper-indented continuation lines — every one
            // of them present in the three targets. `directory.rs` puts serde attributes between
            // fields; `validator.rs` puts a seven-line doc comment in front of `bond_commit`.
            //
            // CAN IT BE DELETED? No — a field declaration in a Rust struct body is DEFINED by sitting
            // at the body's own indent, and without that test the parse yields names no manifest
            // carries, which the ratchet then reports as a phantom gap. The cause is the shape of Rust
            // source, which is outside this file's reach.
            //
            // IT IS ALSO MEASURED rather than argued: the sibling test
            // `the_source_parse_reads_the_struct_it_names_and_not_a_neighbour` asserts each parse
            // returns that struct's own names and nothing another struct carries, and
            // `every_field_of_the_three_structs_declares_whose_state_it_is` fails on any extra name.
            let is_field_line =
                line.len() - t.len() == 4 && !t.starts_with("//") && !t.starts_with("/*");
            if is_field_line {
                let bare = if let Some(x) = t.strip_prefix("pub(crate) ") {
                    x
                } else if let Some(x) = t.strip_prefix("pub ") {
                    x
                } else {
                    t
                };
                if let Some(colon) = bare.find(':') {
                    let name = bare[..colon].trim();
                    let plain = name
                        .chars()
                        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'));
                    if !name.is_empty() && plain {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out
    }

    fn order_book_fields() -> Vec<String> {
        struct_fields(include_str!("../../order_book.rs"), "pub struct OrderBook {")
    }
    fn directory_fields() -> Vec<String> {
        struct_fields(include_str!("../../directory.rs"), "pub struct Directory {")
    }
    fn validator_set_fields() -> Vec<String> {
        struct_fields(
            include_str!("../../validator.rs"),
            "pub struct ValidatorSet {",
        )
    }

    /// The names a manifest does NOT carry, out of a field list. One helper, so the check the ratchet
    /// runs and the check the refutation exercises are literally the same code.
    fn uncovered<'a>(fields: &'a [String], manifest: &[(&str, Authority)]) -> Vec<&'a String> {
        fields
            .iter()
            .filter(|f| !manifest.iter().any(|(n, _)| *n == f.as_str()))
            .collect()
    }

    /// One struct's ratchet: every field classified, no stale entries, and both ceilings honoured.
    fn assert_manifest(
        what: &str,
        fields: &[String],
        manifest: &[(&str, Authority)],
        compared: &[&str],
        max_unclassified: usize,
        max_uncompared: usize,
    ) {
        let n_fields = fields.len();
        assert!(
            n_fields > 0,
            "⛔ the source parse found NO fields in `{what}` — the struct's shape changed and this test \
             is reading the wrong thing. Fix the parse; a manifest checked against nothing is worse \
             than no manifest."
        );

        let missing = uncovered(fields, manifest);
        let n_missing = missing.len();
        assert!(
            missing.is_empty(),
            "⛔ {n_missing} FIELD(S) ADDED TO `{what}` WITH NO AUTHORITY DECLARED: {missing:?}\n\n\
             Every field must say whether the CHAIN decides it or this instance does. That question is \
             the single largest defect class in this project — D-32, D-35, D-36, E-7, D-01, D-29 and \
             the `register_wrapped_asset` hole are all one shape: local state read as truth. Declare it \
             `ChainDerived` (and add it to this struct's `*_COMPARED` list WITH a refutation), or \
             `LocalCache`. `Unclassified` is honest if you genuinely do not know — but it is capped."
        );

        let stale: Vec<&str> = manifest
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !fields.iter().any(|f| f.as_str() == *n))
            .collect();
        let n_stale = stale.len();
        assert!(
            stale.is_empty(),
            "⛔ the `{what}` manifest names {n_stale} field(s) that no longer exist: {stale:?}. A \
             manifest that drifts from the struct is a list nobody can trust — delete them."
        );

        let chain: Vec<&str> = manifest
            .iter()
            .filter(|(_, a)| *a == Authority::ChainDerived)
            .map(|(n, _)| *n)
            .collect();
        let n_chain = chain.len();
        let n_local = manifest
            .iter()
            .filter(|(_, a)| *a == Authority::LocalCache)
            .count();
        let n_undecided = manifest
            .iter()
            .filter(|(_, a)| *a == Authority::Unclassified)
            .count();
        let uncompared: Vec<&&str> = chain.iter().filter(|n| !compared.contains(n)).collect();
        let n_uncompared = uncompared.len();
        let n_compared = compared.len();

        println!(
            "[authority_book] {what}: {n_fields} fields · {n_chain} chain-derived · {n_local} local \
             cache · {n_undecided} UNCLASSIFIED (ceiling {max_unclassified}) · {n_compared} compared · \
             {n_uncompared} NOT YET COMPARED (ceiling {max_uncompared})"
        );

        // Every name claimed as compared must actually BE chain-derived, or the count flatters itself.
        for name in compared {
            assert!(
                chain.contains(name),
                "⛔ `{what}::{name}` is listed as COMPARED but is not declared ChainDerived. Either the \
                 comparison checks something this instance legitimately owns (and will report phantom \
                 findings), or the manifest is wrong. Both are worse than the gap this measures."
            );
        }

        assert!(
            n_undecided <= max_unclassified,
            "⛔ THE UNDECIDED BACKLOG GREW for `{what}`: {n_undecided} unclassified against a ceiling \
             of {max_unclassified}. This number may be LOWERED and never raised — a field arriving \
             without a ruling on whose state it is is exactly how local state becomes truth at some \
             future door."
        );
        assert!(
            n_uncompared <= max_uncompared,
            "⛔ THE UNCOMPARED CHAIN-DERIVED SURFACE GREW for `{what}`: {n_uncompared} field(s) are \
             declared to be the CHAIN's and are never compared against a chain-replay instance, \
             against a ceiling of {max_uncompared}. Every one is a field where an instance could hold a \
             value no block produced and nothing would notice. This number may be LOWERED and never \
             raised.\n\nNot yet compared: {uncompared:?}"
        );
    }

    /// ⛔⛔⛔ NO FIELD OF THESE THREE STRUCTS MAY EXIST WITHOUT AN ANSWER TO "WHOSE STATE IS THIS?"
    ///
    /// The ratchet, all three structs, both ceilings. A field added to any of them with no ruling fails
    /// the build; the undecided backlog and the declared-but-uncompared surface may only shrink.
    #[test]
    fn every_field_of_the_three_structs_declares_whose_state_it_is() {
        assert_manifest(
            "OrderBook",
            &order_book_fields(),
            ORDER_BOOK_MANIFEST,
            ORDER_BOOK_COMPARED,
            MAX_UNCLASSIFIED_ORDER_BOOK,
            MAX_UNCOMPARED_ORDER_BOOK,
        );
        assert_manifest(
            "Directory",
            &directory_fields(),
            DIRECTORY_MANIFEST,
            DIRECTORY_COMPARED,
            MAX_UNCLASSIFIED_DIRECTORY,
            MAX_UNCOMPARED_DIRECTORY,
        );
        assert_manifest(
            "ValidatorSet",
            &validator_set_fields(),
            VALIDATOR_SET_MANIFEST,
            VALIDATOR_SET_COMPARED,
            MAX_UNCLASSIFIED_VALIDATOR_SET,
            MAX_UNCOMPARED_VALIDATOR_SET,
        );
    }

    /// ⭐⭐ THE MANIFEST CHECK ITSELF IS REFUTED — it must be able to SEE an unclassified field.
    ///
    /// A manifest test that cannot detect a missing entry is the same failure as a detector that cannot
    /// fire: it reports green forever while the gap it exists to close reopens. So the lookup is run on
    /// a synthetic field list carrying a name no manifest holds, once per struct, and required to find
    /// exactly that name.
    ///
    /// The negative half matters equally: each REAL field list must come back fully covered, or the
    /// positive result would just mean the manifests are empty.
    #[test]
    fn the_manifest_check_detects_a_field_none_of_the_three_manifests_carry() {
        let planted = "a_field_nobody_classified".to_string();
        for (what, real, manifest) in [
            ("OrderBook", order_book_fields(), ORDER_BOOK_MANIFEST),
            ("Directory", directory_fields(), DIRECTORY_MANIFEST),
            (
                "ValidatorSet",
                validator_set_fields(),
                VALIDATOR_SET_MANIFEST,
            ),
        ] {
            // POSITIVE — one real field plus one the manifest does not carry.
            let probe = vec![real[0].clone(), planted.clone()];
            let found = uncovered(&probe, manifest);
            let n_found = found.len();
            assert_eq!(
                n_found, 1,
                "⛔ THE `{what}` MANIFEST CHECK IS BLIND: handed a field list containing a name the \
                 manifest does NOT carry, it reported {found:?}. Then a field can be added to that \
                 struct with no ruling on whose state it is and nothing objects — which is exactly how \
                 local state becomes truth at some future door."
            );
            assert_eq!(
                found[0], &planted,
                "⛔ the `{what}` check must name the UNCOVERED field, not an arbitrary one"
            );

            // NEGATIVE HALF — the real struct must come back fully covered, or the above proves nothing.
            let real_gaps = uncovered(&real, manifest);
            assert!(
                real_gaps.is_empty(),
                "⛔ {what} has uncovered real field(s) {real_gaps:?} — see the sibling test"
            );
        }
    }

    /// ⛔ THE PARSE MUST BE READING THE STRUCTS IT NAMES. The three field sets are disjoint and each
    /// holds a name only that struct has; a parse that silently latched onto a neighbouring struct — or
    /// onto `Node`, which has 142 fields and would swallow anything — would otherwise look like a green
    /// manifest. Same failure mode as `authority.rs`'s `fields.len() > 100` floor, spelled out per
    /// struct because these structs are small enough that a count says nothing.
    #[test]
    fn the_source_parse_reads_the_struct_it_names_and_not_a_neighbour() {
        let (b, d, v) = (
            order_book_fields(),
            directory_fields(),
            validator_set_fields(),
        );
        assert!(
            b.contains(&"orders".to_string()),
            "OrderBook parse: got {b:?}"
        );
        assert!(
            d.contains(&"names".to_string()) && d.contains(&"persist_path".to_string()),
            "Directory parse: got {d:?}"
        );
        assert!(
            v.contains(&"bonds".to_string()) && v.contains(&"bond_commit".to_string()),
            "ValidatorSet parse: got {v:?}"
        );
        for name in b.iter().chain(d.iter()) {
            assert!(
                !v.contains(name),
                "⛔ `{name}` appears in TWO of the three parses — the parse ran past a closing brace \
                 and is reading a struct it does not name."
            );
        }
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod comparisons {
    //! **THE COMPARISONS, AND THE REFUTATION OF EVERY ONE OF THEM.**
    //!
    //! METHOD, taken from `harness::fuzz::selfproof`: build an HONEST pair through the real doors and
    //! require SILENCE; then mutate exactly the field the comparison is about, ASSERT THE MUTATION
    //! MOVED SOMETHING, and require the comparison to report it and to NAME the field.
    //!
    //! ⛔ THE NON-VACUITY ASSERTION IS NOT OPTIONAL AND IT IS NOT CEREMONY. It caught a test about to
    //! pass for the wrong reason FIVE times in the 2026-09-08 sweep, four of them written by an author
    //! who believed the mutation worked (`record_note_payload_for` with an invented block id never took
    //! an ordinal; `Node::params` was written while `Node::params()` read the DAG's copy — 15000 ->
    //! 15000). When one of these fails, the CONSTRUCTION is wrong. Never the assertion.

    use super::*;
    use crate::directory::{DirEntry, Directory, KIND_GROUP, KIND_NAME, KIND_PROFILE};
    use crate::order_book::{OrderBook, RestingOrder};
    use crate::validator::ValidatorSet;
    use usdm_decider::whir_rec_block::{
        prove_order_maker_half, wrapped_asset_tag_u32, MakerHalfWitness, OrderTerms, USDM_ASSET_TAG,
    };

    const EXPIRES: u64 = 10_000;

    // ───────────────────────────────────────────────────────────────────────────────────────────
    // THE COMPARISONS. Each reads exactly the fields its struct's `*_COMPARED` list names, and each
    // finding NAMES the field — a reader chasing a double payout must not be sent to the unspent set.
    // ───────────────────────────────────────────────────────────────────────────────────────────

    /// `OrderBook::orders` — WHICH LOTS ARE STILL LIVE, not how many.
    fn book_disagreement(chain: &OrderBook, party: &OrderBook) -> Option<String> {
        let (c, p) = (
            chain.resting_census_for_audit(),
            party.resting_census_for_audit(),
        );
        if c == p {
            return None;
        }
        let (n_party, n_chain) = (p.len(), c.len());
        let party_lots: Vec<u64> = p.iter().map(|n| n[0]).collect();
        let chain_lots: Vec<u64> = c.iter().map(|n| n[0]).collect();
        Some(format!(
            "`OrderBook::orders`: the party holds {n_party} live resting order(s) where an instance fed \
             only the chain's events holds {n_chain}, and the SETS differ (party {party_lots:?}, chain \
             {chain_lots:?}). An order book is state and must be a function of the chain: if a fill \
             retired an order on the node that SAW it and nowhere else, the maker's lot is still live \
             everywhere else and the same lot pays out twice. That is the 2026-09-03 incident, and \
             every node involved was individually correct."
        ))
    }

    /// `Directory::{names,groups,profiles,acc}` — WHAT THIS REGISTRY RESOLVES, then what it folded.
    ///
    /// The maps are checked BEFORE the accumulator deliberately: they are the earlier and more specific
    /// symptom, and they are what a payment actually reads.
    fn directory_disagreement(chain: &Directory, party: &Directory) -> Option<String> {
        let (c, p) = (
            chain.projection_digest_for_audit(),
            party.projection_digest_for_audit(),
        );
        for (i, (field, why)) in [
            (
                "names",
                "`#64 Pay @username` sends money to whoever this map resolves, so a party holding a \
                 different one sends a user's funds to the WRONG OWNER while every node stays \
                 individually correct",
            ),
            (
                "groups",
                "a Letter joiner seals its join request to this map's `owner_addr`, so a party holding \
                 a different one hands the joiner to somebody else's key",
            ),
            (
                "profiles",
                "this map carries `fee_micro`, the DM-acceptance PRICE in micro-USDm, so a party \
                 holding a different one quotes a price the chain never set",
            ),
            (
                "collections",
                "a collection's owner decides which pieces may be filed under it and the marketplace lists its \
                 pieces from here, so a party holding a different one shows buyers a collection the chain never made",
            ),
            (
                "assets",
                "an asset's name, picture, creator, collection and supply are what a buyer reads before paying, \
                 so a party holding a different record names or prices a token the chain never created",
            ),
            (
                "asset_tags",
                "a wallet names the notes it holds through this index, so a party holding a different one shows a \
                 holder another asset's name for what it holds",
            ),
            (
                "collection_order",
                "the marketplace's newest-first page reads collections by this order, so a party holding a \
                 different one lists a market the chain never ordered",
            ),
        ]
        .iter()
        .enumerate()
        {
            if c[i] != p[i] {
                let (pd, pn) = (format!("{:02x?}", &p[i].0[..4]), p[i].1);
                let (cd, cn) = (format!("{:02x?}", &c[i].0[..4]), c[i].1);
                return Some(format!(
                    "`Directory::{field}`: the party's projection digests to {pd} over {pn} record(s) \
                     where an instance fed only the chain's entries digests to {cd} over {cn} — {why}."
                ));
            }
        }
        if chain.acc != party.acc {
            let (pd, cd) = (
                format!("{:02x?}", &party.acc[..4]),
                format!("{:02x?}", &chain.acc[..4]),
            );
            return Some(format!(
                "`Directory::acc`: the party folded to {pd} where an instance fed only the chain's \
                 entries folds to {cd}. This accumulator rides the DSYNC sync state, so a party that \
                 disagrees advertises a registry endpoint the mesh did not certify."
            ));
        }
        None
    }

    /// `ValidatorSet::{bonds,total_bond,slashed,slashed_bond_burned,bond_commit,custody,kem_eks}` — read
    /// through the snapshot's OWN deterministic export, so the comparison cannot drift from what a
    /// restart actually carries.
    fn validator_set_disagreement(chain: &ValidatorSet, party: &ValidatorSet) -> Option<String> {
        let (cb, cs, csb, cbc, ccu) = chain.export_state();
        let (pb, ps, psb, pbc, pcu) = party.export_state();
        if cb != pb {
            let n = pb.len();
            return Some(format!(
                "`ValidatorSet::bonds`: the party's bonded MEMBERSHIP differs from an instance fed only \
                 the chain's bond set ({n} member(s) either side). Every ≥2/3 threshold in the peg is \
                 summed over these entries, so two nodes that disagree here weigh mint and redeem \
                 authority differently — and a size comparison cannot see it, because the counts match."
            ));
        }
        let (pt, ct) = (party.total_bond(), chain.total_bond());
        if ct != pt {
            return Some(format!(
                "`ValidatorSet::total_bond`: the party's bonded weight is {pt} where an instance fed \
                 only the chain's bond set reaches {ct}. This figure is the DENOMINATOR of every ≥2/3 \
                 gate (`weight * 3 >= 2 * total_bond`), so a party holding a smaller one finalises on \
                 less than two-thirds of the real weight and a party holding a larger one refuses a \
                 quorum the mesh accepted."
            ));
        }
        if cs != ps {
            let (np, nc) = (ps.len(), cs.len());
            return Some(format!(
                "`ValidatorSet::slashed`: the party bars {np} proven double-signer(s) where an instance \
                 fed only the chain bars {nc}. A slashed id may NEVER re-admit; a party that does not \
                 hold the same set will re-seat one, and the economic teeth that make a stake-based \
                 finality attack cost money stop biting."
            ));
        }
        if csb != psb {
            return Some(format!(
                "`ValidatorSet::slashed_bond_burned`: the party says {psb} units left the bonded weight \
                 forever where an instance fed only the chain says {csb}. That is supply that moved, \
                 and supply moves only via chain objects."
            ));
        }
        if cbc != pbc {
            return Some(format!(
                "`ValidatorSet::bond_commit`: the party's confidential bonded-stake digest is {pbc:?} \
                 where an instance fed only the chain reaches {cbc:?}. Every admit/unbond/slash is \
                 accepted against THIS digest (`verify_bond_admit` / `verify_bond_reduce`), so a party \
                 holding a different one accepts conservation proofs the mesh refuses and refuses ones \
                 it accepts."
            ));
        }
        if ccu != pcu {
            let (np, nc) = (pcu.len(), ccu.len());
            return Some(format!(
                "`ValidatorSet::custody`: the party holds {np} bridge-custody share(s) where an \
                 instance fed only the chain holds {nc}. `bonded_custody()` is the key-aggregate the \
                 BTC and XMR RESERVE DEPOSIT ADDRESSES are derived from and served over the reserve \
                 route — so two nodes that disagree hand a depositing user DIFFERENT addresses, and at \
                 most one of them is controlled by the quorum. The user's real coin goes to the other."
            ));
        }
        let (pk, ck) = (party.bonded_custodian_eks(), chain.bonded_custodian_eks());
        if ck != pk {
            let (np, nc) = (pk.len(), ck.len());
            return Some(format!(
                "`ValidatorSet::kem_eks`: the party holds {np} custodian encapsulation key(s) where an \
                 instance fed only the chain holds {nc}. `bonded_custodian_eks()` is what a peg-in or \
                 peg-out proposal seals its (deposit, mint) / (release, burn) delta TO — so a party that \
                 disagrees here seals a custodian's share to a key that custodian does not hold (it can \
                 never attest, and the quorum never forms) or to a key a stranger holds (the confidential \
                 total leaves the custodian set). The keys ride the seat header under the seat signature \
                 and the certified DSYNC state; nothing else may set them."
            ));
        }
        let (pf, cf) = (party.finality_seats(), chain.finality_seats());
        if cf != pf {
            let (np, nc) = (pf.len(), cf.len());
            return Some(format!(
                "`ValidatorSet::finality_bonds`: the party seats {np} finality member(s) where an instance fed only the \
                 chain seats {nc} (or the same members at other weights). A vote's finality weight is its custody seat \
                 PLUS its finality seat, so a member seated on one side only counts there and is `NoWeight` on the other: \
                 the two disagree about whether a block is final."
            ));
        }
        let (pt, ct) = (party.total_finality_weight(), chain.total_finality_weight());
        if ct != pt {
            return Some(format!(
                "`ValidatorSet::total_finality`: the party's finality denominator is {pt} where an instance fed only \
                 the chain reaches {ct}. Finality asks `weight * 3 >= 2 * total`, so a smaller one finalises on less than \
                 two-thirds of the real weight and a larger one refuses a quorum the mesh accepted."
            ));
        }
        // G2b: the view at a height — `seat_activations()` is the exact export the snapshot and the bundle carry.
        let (pa, ca) = (party.seat_activations(), chain.seat_activations());
        if ca.0 != pa.0 {
            return Some(format!(
                "`ValidatorSet::bond_active_from`: the party activates its custody seats at {:?} where an instance fed only \
                 the chain activates them at {:?}. Finality is judged against the set active at the VOTED height, so a seat \
                 active earlier on one side counts toward a quorum there and is `NoWeight` on the other.",
                pa.0, ca.0
            ));
        }
        if ca.1 != pa.1 {
            return Some(format!(
                "`ValidatorSet::finality_active_from`: the party activates its finality seats at {:?} where an instance fed \
                 only the chain activates them at {:?} — the same quorum split, on the free / USDm seats.",
                pa.1, ca.1
            ));
        }
        if ca.2 != pa.2 {
            return Some(format!(
                "`ValidatorSet::departed_bond`: the party keeps the departed custody rows {:?} where an instance fed only \
                 the chain keeps {:?}. A departed row is the weight a vote below the exit's activation height is still \
                 judged against; a side without it finalises on a smaller denominator.",
                pa.2, ca.2
            ));
        }
        if ca.3 != pa.3 {
            return Some(format!(
                "`ValidatorSet::departed_finality`: the party keeps the departed finality rows {:?} where an instance fed \
                 only the chain keeps {:?} — the same denominator split, on the finality seats.",
                pa.3, ca.3
            ));
        }
        // §BR-3 17.3 / 17.6: the seat words, through the snapshot's own export
        let (pw, cw) = (party.seat_words(), chain.seat_words());
        let delegated = |w: &[crate::validator::SeatWords]| w.iter().map(|(k, d, _, _)| (*k, *d)).filter(|(_, d)| *d > 0).collect::<Vec<_>>();
        if delegated(&pw) != delegated(&cw) {
            return Some(format!(
                "`ValidatorSet::delegated`: the party holds delegated words {:?} where an instance fed only the chain holds \
                 {:?}. The seat's own locked weight is `bonds − delegated`, so a side with another word re-bonds, unbonds or \
                 pays an Undelegate its peers refuse.",
                delegated(&pw),
                delegated(&cw)
            ));
        }
        let yields = |w: &[crate::validator::SeatWords]| w.iter().map(|(k, _, l, a)| (*k, *l, *a)).filter(|(_, l, a)| l.is_some() || *a > 0).collect::<Vec<_>>();
        if yields(&pw) != yields(&cw) {
            return Some(format!(
                "`ValidatorSet::own_yield`: the party holds own-weight yield words {:?} where an instance fed only the chain \
                 holds {:?} — a BondYieldClaim pays a different amount on each side.",
                yields(&pw),
                yields(&cw)
            ));
        }
        None
    }

    // ───────────────────────────────────────────────────────────────────────────────────────────
    // HONEST INSTANCES — built through the real doors, never hand-rolled.
    // ───────────────────────────────────────────────────────────────────────────────────────────

    fn terms_at(pay_b: u64) -> OrderTerms {
        // DEX-GRID (C3): through the one snap helper.
        OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000),
            pay_b: crate::order_book::snap_to_grid(pay_b),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: crate::order_book::snap_expiry(EXPIRES),
        }
    }

    /// A REAL resting order, proved by a real maker half and carrying the payout note a maker really
    /// builds — the same helper shape `order_book::tests` uses, because an order `post` would refuse is
    /// not an honest instance of anything.
    fn order(seed: u64, pay_b: u64) -> RestingOrder {
        let t = terms_at(pay_b);
        let (bytes, maker) = prove_order_maker_half(
            &MakerHalfWitness {
                owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[seed, seed + 1, seed + 2, seed + 3])),
                payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[seed + 10, seed + 11, seed + 12, seed + 13]),
                lc_blind: crate::spend_frontier::TEST_LC_BLIND,
            },
            &t,
        )
        .expect("maker half proves");
        let mut payout_note = vec![0u8; 1153];
        payout_note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));
        RestingOrder {
            terms: t,
            maker,
            maker_bytes: bytes,
            payout_note,
            membership_carrier: crate::order_book::test_membership_bind().0,
            membership_tip: crate::order_book::test_membership_bind().1,
            payout_clue: crate::order_book::test_payout_clue(),
        }
    }

    /// Two books fed the SAME orders in OPPOSITE arrival order — a real mesh has no shared arrival
    /// order, and a comparison that depended on one would report every honest pair.
    fn honest_book_pair(a: &RestingOrder, b: &RestingOrder) -> (OrderBook, OrderBook) {
        let mut chain = OrderBook::new();
        let mut party = OrderBook::new();
        chain.post(a.clone(), 1).expect("chain: a rests");
        chain.post(b.clone(), 1).expect("chain: b rests");
        party.post(b.clone(), 1).expect("party: b rests");
        party.post(a.clone(), 1).expect("party: a rests");
        (chain, party)
    }

    fn owner(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    fn entry(kind: u8, key: &str, address: &str, name: &str, topic: &str) -> DirEntry {
        DirEntry {
            kind,
            key: key.into(),
            address: address.into(),
            name: name.into(),
            topic: topic.into(),
            pubkey: vec![1],
            sig: vec![2],
            pic: None,
        }
    }

    /// A registry that applied AND folded the same entries, exactly as `Node::apply_dir_set` does:
    /// *"Projection, log and accumulator advance in ONE act."*
    fn honest_directory() -> Directory {
        let mut d = Directory::new();
        for e in [
            entry(KIND_NAME, "alice", "addrAlice", "", ""),
            entry(KIND_GROUP, "rustdevs", "cZ1", "Rust Devs", "programming"),
            entry(
                KIND_PROFILE,
                "cZprofile",
                "cZprofile",
                "Cas",
                &format!("bio{}250000", '\u{1f}'),
            ),
        ] {
            assert!(d.apply_entry(&e, owner(1)), "the honest entry applies");
            d.fold_applied(&e);
        }
        d
    }

    fn vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    /// Two bonded validators at the base floor, one with a registered bridge-custody share, and a
    /// seeded confidential bond commitment — every field the comparison reads is non-default, so a
    /// silent comparison cannot be silence over an empty set.
    fn honest_validator_set() -> ValidatorSet {
        let mut s = ValidatorSet::new();
        s.admit(vid(1), 2_000, 0)
            .expect("v1 bonds at the base floor");
        s.admit(vid(2), 2_000, 0)
            .expect("v2 bonds at the base floor");
        s.register_custody(vid(1), vec![0x02; 33], [0x11; 32]);
        s.initialize_bond_commitment(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]));
        s
    }

    // ───────────────────────────────────────────────────────────────────────────────────────────
    // ORDER BOOK — 1 field, 1 comparison, refuted twice (the violation, and the gap it closes).
    // ───────────────────────────────────────────────────────────────────────────────────────────

    /// ⭐⭐⭐ `OrderBook::orders` — THE 2026-09-03 DOUBLE PAYOUT, AS A STATE.
    ///
    /// A fill retires the maker's lot by burning its resting nullifier. E-7 was that burn applied on
    /// the node that saw the fill and NOWHERE ELSE, so the lot stayed live for every other node and the
    /// same lot paid out twice — with both nodes individually correct. That is exactly the mutation
    /// below: one book retires an order the other still holds.
    #[test]
    fn book_orders_comparison_fires_when_a_lot_is_retired_on_one_node_only() {
        let (a, b) = (order(100, 200_000), order(200, 200_000));

        // NEGATIVE CONTROL FIRST — two books fed the same orders in OPPOSITE order must be silent. A
        // comparison that fires on an honest pair protects nothing and trains its readers to ignore it.
        let (chain, party) = honest_book_pair(&a, &b);
        assert_eq!(
            book_disagreement(&chain, &party),
            None,
            "⛔ THE ORDER-BOOK COMPARISON FIRES ON AN HONEST PAIR: two books fed the SAME orders, only \
             in a different arrival order, are the same book. A detector that always fires is worse \
             than none."
        );

        // THE REFUTATION — the fill's burn lands on ONE side only.
        let (chain, mut party) = honest_book_pair(&a, &b);
        let before = party.resting_census_for_audit();
        assert!(
            party.remove_by_nullifier(a.maker.nullifier),
            "the retirement door must actually retire the lot"
        );
        let after = party.resting_census_for_audit();
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the party's book still holds the same lots \
             ({before:?}), so the assertion below would pass for the wrong reason. Fix the \
             construction, never the assertion."
        );

        let fired = book_disagreement(&chain, &party).expect(
            "⛔ THE ORDER-BOOK COMPARISON CANNOT FIRE. One book retired a maker's lot and the other \
             still holds it — the 2026-09-03 shape — and the comparison was silent. Then a book entry \
             alive on one node and retired on another is invisible, and the same maker's lot pays out \
             twice while both nodes self-verify correctly.",
        );
        assert!(
            fired.contains("OrderBook::orders"),
            "the finding must NAME the order book, or a reader chasing a double payout is sent to the \
             unspent set instead: got {fired}"
        );
    }

    /// ⭐⭐⭐ AND THE GAP IT CLOSES: THE COUNT IS EQUAL AND THE BOOKS ARE NOT THE SAME BOOK.
    ///
    /// `Sim::cold_peer_verdict` compares `order_book_len_for_audit()` — a COUNT. E-7 is an IDENTITY
    /// question: *whose lot is still live*. Two nodes each holding ONE order that is a DIFFERENT one is
    /// the double payout with the count intact, and this test is the measurement that says so: the
    /// length read is asserted EQUAL on the very state the census reports.
    #[test]
    fn the_length_read_is_silent_on_two_books_holding_different_lots() {
        let (a, b) = (order(300, 200_000), order(400, 200_000));
        let mut chain = OrderBook::new();
        let mut party = OrderBook::new();
        chain.post(a.clone(), 1).expect("chain holds a");
        party.post(b.clone(), 1).expect("party holds b");

        assert_ne!(
            a.maker.nullifier, b.maker.nullifier,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the two lots must be DIFFERENT notes, or the books \
             genuinely agree and nothing below means anything."
        );
        assert_eq!(
            chain.len(),
            party.len(),
            "⛔ THE GAP WAS NOT CONSTRUCTED: this test exists to show the COUNT read cannot see the \
             difference, so the counts must match."
        );

        let fired = book_disagreement(&chain, &party).expect(
            "⛔ THE CENSUS IS NO STRONGER THAN THE COUNT: two books holding one DIFFERENT lot each — \
             one maker's offer live where the chain retired it, another retired where the chain holds \
             it — and the comparison was silent. `order_book_len_for_audit` is equal on this state, so \
             if the census is equal too then nothing in the tree can see E-7 at constant depth.",
        );
        assert!(
            fired.contains("OrderBook::orders"),
            "the finding must NAME the order book: got {fired}"
        );
    }

    // ───────────────────────────────────────────────────────────────────────────────────────────
    // DIRECTORY — 4 comparisons, each refuted separately.
    // ───────────────────────────────────────────────────────────────────────────────────────────

    /// ⭐⭐⭐ `Directory::names` — THE MISDIRECTED PAYMENT, AND THE PROOF THAT `dir_acc` CANNOT SEE IT.
    ///
    /// `#64 Pay @username` sends money to whoever `resolve_name` returns. `Sim::cold_peer_verdict`
    /// compares `dir_acc()` — the fold over APPLIED ENTRY BYTES, advanced by `fold_applied`. The map is
    /// advanced by `apply_entry`. They are two separate calls (`node.rs:23139` then `:23142`), so this
    /// mutation moves the resolution and leaves the accumulator EXACTLY where it was: the party now
    /// resolves `@alice` to an address the chain never carried, and the read that exists today is
    /// silent on it byte for byte.
    #[test]
    fn directory_names_comparison_fires_on_a_resolution_the_accumulator_does_not_show() {
        // NEGATIVE CONTROL — two registries fed the same entries agree.
        assert_eq!(
            directory_disagreement(&honest_directory(), &honest_directory()),
            None,
            "⛔ THE DIRECTORY COMPARISON FIRES ON AN HONEST PAIR: two registries that applied and \
             folded the same entries are the same registry."
        );

        let chain = honest_directory();
        let mut party = honest_directory();
        let acc_before = party.acc;
        let before = party.projection_digest_for_audit();

        // The projection moves; the accumulator is NOT folded — the two are separate calls.
        assert!(
            party.apply_entry(&entry(KIND_NAME, "alice", "addrATTACKER", "", ""), owner(1)),
            "the re-point must land in the projection"
        );

        let after = party.projection_digest_for_audit();
        assert_ne!(
            after[0], before[0],
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the `names` projection did not move, so the \
             assertion below would pass for the wrong reason. Fix the construction, never the assertion."
        );
        assert_eq!(
            party.resolve_name("alice"),
            Some("addrATTACKER"),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: `@alice` must actually resolve to the address the \
             chain never carried — that resolution IS the misdirected payment."
        );
        assert_eq!(
            party.acc, acc_before,
            "⛔ THE GAP WAS NOT CONSTRUCTED: this test exists to show the ACCUMULATOR read cannot see a \
             projection change, so `acc` must be unmoved. If it moved, `apply_entry` gained a fold and \
             this test should be rewritten rather than relaxed."
        );
        assert_eq!(
            chain.acc, party.acc,
            "⛔ AND THE READ THAT EXISTS TODAY MUST BE EQUAL ON THIS STATE — that is the finding: \
             `Sim::cold_peer_verdict` compares `dir_acc()` and nothing else."
        );

        let fired = directory_disagreement(&chain, &party).expect(
            "⛔ THE `names` COMPARISON CANNOT FIRE. A party resolves `@alice` to an address no block \
             carried, its accumulator matches the chain's byte for byte, and the comparison was \
             silent. `#64 Pay @username` sends money to whoever the directory resolves — so this is a \
             user's funds delivered to the wrong owner, with every node individually correct.",
        );
        assert!(
            fired.contains("Directory::names"),
            "the finding must NAME the resolution map, not the accumulator: got {fired}"
        );
    }

    /// `Directory::groups` — a joiner seals its join request to `owner_addr`, so a party holding a
    /// different one hands the joiner to somebody else's key. Same construction: the projection moves
    /// and the accumulator does not, so the existing read stays silent.
    #[test]
    fn directory_groups_comparison_fires_on_a_handle_repointed_to_another_owner() {
        assert_eq!(
            directory_disagreement(&honest_directory(), &honest_directory()),
            None,
            "⛔ THE DIRECTORY COMPARISON FIRES ON AN HONEST PAIR"
        );

        let chain = honest_directory();
        let mut party = honest_directory();
        let before = party.projection_digest_for_audit();
        assert!(
            party.apply_entry(
                &entry(
                    KIND_GROUP,
                    "rustdevs",
                    "cZATTACKER",
                    "Rust Devs",
                    "programming"
                ),
                owner(1)
            ),
            "the re-point must land in the projection"
        );
        let after = party.projection_digest_for_audit();
        assert_ne!(
            after[1], before[1],
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the `groups` projection did not move. Fix the \
             construction, never the assertion."
        );
        assert_eq!(
            party.resolve_group("rustdevs").map(|r| r.owner_addr.as_str()),
            Some("cZATTACKER"),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the handle must actually resolve to the other owner"
        );

        let fired = directory_disagreement(&chain, &party).expect(
            "⛔ THE `groups` COMPARISON CANNOT FIRE: a party points a group handle at an owner address \
             no block carried and the comparison was silent.",
        );
        assert!(
            fired.contains("Directory::groups"),
            "the finding must NAME the group map: got {fired}"
        );
    }

    /// `Directory::{collections,assets,asset_tags,collection_order}` — what the marketplace lists and what a buyer reads
    /// before paying. A party holding a collection or an asset record the chain never made shows buyers a market and a
    /// token nobody created.
    #[test]
    fn directory_market_maps_comparison_fires_on_a_collection_and_an_asset_the_chain_never_made() {
        // (spec §12.6's four maps, declared `ChainDerived` 2026-11-12 by lane goods, which added them)
        // A COLLECTION the chain never applied: `collections` and `collection_order` both move, and the finding names
        // the map a buyer reads
        let chain = honest_directory();
        let mut party = honest_directory();
        let before = party.projection_digest_for_audit();
        let apes = DirEntry { kind: crate::directory::KIND_COLLECTION, key: "apes".into(), address: String::new(), name: "Apes".into(), topic: "a forged market".into(), pubkey: vec![1], sig: vec![2], pic: None };
        assert!(party.apply_entry(&apes, owner(2)), "the collection must land in the projection");
        let after = party.projection_digest_for_audit();
        assert!(
            after[3] != before[3] && after[6] != before[6],
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: `collections` and `collection_order` did not both move. Fix the construction, never the assertion."
        );
        let fired = directory_disagreement(&chain, &party).expect("⛔ THE `collections` COMPARISON CANNOT FIRE: a party lists a collection the chain never made, and the comparison was silent.");
        assert!(fired.contains("Directory::collections"), "the finding must NAME the collections map: got {fired}");
        // AN ASSET RECORD the chain never wrote: `assets` and `asset_tags` both move
        let mut party = honest_directory();
        let before = party.projection_digest_for_audit();
        let hex = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        let record = DirEntry {
            kind: crate::directory::KIND_ASSET,
            key: hex(&[0x5au8; 32]),
            address: hex(&owner(3)),
            name: crate::directory::asset_facts_field(false, "FAKE", "A token nobody created", &[0u8; 32]),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: None,
        };
        assert!(party.apply_asset_record(&record).is_some(), "the record must land in the projection");
        let after = party.projection_digest_for_audit();
        assert!(
            after[4] != before[4] && after[5] != before[5],
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: `assets` and `asset_tags` did not both move. Fix the construction, never the assertion."
        );
        let fired = directory_disagreement(&chain, &party).expect("⛔ THE `assets` COMPARISON CANNOT FIRE: a party names a token the chain never created, and the comparison was silent.");
        assert!(fired.contains("Directory::assets"), "the finding must NAME the assets map: got {fired}");
    }

    /// `Directory::profiles` — this map carries `fee_micro`, the DM-acceptance PRICE in micro-USDm. A
    /// party holding a different one quotes a price the chain never set, so a sender pays the wrong
    /// amount to be heard.
    #[test]
    fn directory_profiles_comparison_fires_on_a_dm_fee_the_chain_never_set() {
        assert_eq!(
            directory_disagreement(&honest_directory(), &honest_directory()),
            None,
            "⛔ THE DIRECTORY COMPARISON FIRES ON AN HONEST PAIR"
        );

        let chain = honest_directory();
        let mut party = honest_directory();
        let fee_before = party
            .resolve_profile("cZprofile")
            .map(|p| p.fee_micro)
            .expect("the honest profile resolves");
        let before = party.projection_digest_for_audit();
        assert!(
            party.apply_entry(
                &entry(
                    KIND_PROFILE,
                    "cZprofile",
                    "cZprofile",
                    "Cas",
                    &format!("bio{}999000000", '\u{1f}')
                ),
                owner(1)
            ),
            "the fee change must land in the projection"
        );
        let after = party.projection_digest_for_audit();
        let fee_after = party
            .resolve_profile("cZprofile")
            .map(|p| p.fee_micro)
            .expect("still resolves");
        assert_ne!(
            after[2], before[2],
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the `profiles` projection did not move. Fix the \
             construction, never the assertion."
        );
        assert_ne!(
            fee_after, fee_before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the DM-acceptance PRICE must actually change — an \
             identical fee would make this a test about a re-publish, not about a price nobody set."
        );

        let fired = directory_disagreement(&chain, &party).expect(
            "⛔ THE `profiles` COMPARISON CANNOT FIRE: a party quotes a DM-acceptance fee the chain \
             never set, and the comparison was silent.",
        );
        assert!(
            fired.contains("Directory::profiles"),
            "the finding must NAME the profile map: got {fired}"
        );
    }

    /// `Directory::acc` — the accumulator itself, which rides the DSYNC sync state. A party that
    /// disagrees advertises a registry endpoint the mesh did not certify, and a refill target derived
    /// from it re-delivers the wrong sequence.
    #[test]
    fn directory_acc_comparison_fires_on_a_fold_no_entry_produced() {
        assert_eq!(
            directory_disagreement(&honest_directory(), &honest_directory()),
            None,
            "⛔ THE DIRECTORY COMPARISON FIRES ON AN HONEST PAIR"
        );

        let chain = honest_directory();
        let mut party = honest_directory();
        let before = party.acc;
        party.acc = [0x5Au8; 32];
        assert_ne!(
            party.acc, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the accumulator did not move. Fix the \
             construction, never the assertion."
        );
        assert_eq!(
            party.projection_digest_for_audit(),
            chain.projection_digest_for_audit(),
            "⛔ THE MUTATION MUST MOVE ONLY THE ACCUMULATOR — a projection change would make this the \
             `names` test again and leave `acc` unrefuted."
        );

        let fired = directory_disagreement(&chain, &party).expect(
            "⛔ THE `acc` COMPARISON CANNOT FIRE: a party folded to an endpoint no entry produced and \
             the comparison was silent.",
        );
        assert!(
            fired.contains("Directory::acc"),
            "the finding must NAME the accumulator: got {fired}"
        );
    }

    // ───────────────────────────────────────────────────────────────────────────────────────────
    // VALIDATOR SET — 6 comparisons, each refuted separately and each isolated to ONE field.
    //
    // Four of the six are driven through `import_state` — the REAL snapshot-restore door, which is how
    // a node actually acquires a set it did not derive. Driving the real door beats a setter: D-36 was
    // exactly a joiner that KEPT state a restore handed it.
    // ───────────────────────────────────────────────────────────────────────────────────────────

    /// ⭐⭐ `ValidatorSet::bonds` — SAME SIZE, SAME TOTAL, DIFFERENT MEMBERS.
    ///
    /// `Sim::cold_peer_verdict` compares `validators().len()`. This state has equal length AND equal
    /// total bonded weight, and is still two different validator sets: a vote by `vid(2)` counts on one
    /// node and is `NoWeight` on the other, so the two disagree about whether a block is final.
    #[test]
    fn validator_bonds_comparison_fires_on_a_different_membership_of_the_same_size() {
        // NEGATIVE CONTROL — an exact snapshot round-trip must be silent, or every honest restart is a
        // finding.
        let chain = honest_validator_set();
        let (b, s, sb, bc, cu) = chain.export_state();
        let mut restored = ValidatorSet::new();
        restored.import_state(b.clone(), s.clone(), sb, bc, cu.clone());
        assert_eq!(
            validator_set_disagreement(&chain, &restored),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST RESTORE: a set re-imported from its own \
             export is the same set. A comparison that reports every restart protects nothing."
        );

        // THE REFUTATION — vid(2)'s bond moved to vid(3). Same count, same total, different set.
        let mut party = ValidatorSet::new();
        party.admit(vid(1), 2_000, 0).expect("v1 bonds");
        party.admit(vid(3), 2_000, 0).expect("v3 bonds");
        party.register_custody(vid(1), vec![0x02; 33], [0x11; 32]);
        party.initialize_bond_commitment(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]));

        assert_ne!(
            party.export_state().0,
            chain.export_state().0,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the two memberships are identical. Fix the \
             construction, never the assertion."
        );
        assert_eq!(
            party.len(),
            chain.len(),
            "⛔ THE GAP WAS NOT CONSTRUCTED: this test exists to show the SIZE read cannot see a \
             membership swap, so the sizes must match."
        );
        assert_eq!(
            party.total_bond(),
            chain.total_bond(),
            "⛔ THE GAP WAS NOT CONSTRUCTED: the totals must match too, or this would be the \
             `total_bond` refutation wearing a different name."
        );
        assert_eq!(
            party.bond_of(&vid(2)),
            0,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: `vid(2)` must carry weight on one side and none on \
             the other — that asymmetry IS the disagreement about who can finalise."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `bonds` COMPARISON CANNOT FIRE: two sets of equal size and equal total bonded \
             weight hold entirely different members, and the comparison was silent. `len()` is equal \
             on this state, so if the membership read is equal too then nothing in the tree can see a \
             swapped validator.",
        );
        assert!(
            fired.contains("ValidatorSet::bonds"),
            "the finding must NAME the membership: got {fired}"
        );
    }

    /// ⭐⭐⭐ SATOSHI §6 — `ValidatorSet::finality_bonds`: the same custody set with a DIFFERENT finality seat. Driven through
    /// `import_finality_state`, the real snapshot/bundle restore door. NEGATIVE CONTROL: an exact round trip is silent.
    #[test]
    fn validator_finality_seat_comparison_fires_when_one_side_seats_a_member_the_other_does_not() {
        let mut chain = honest_validator_set();
        chain.admit_finality(vid(4), 1_000).expect("v4 takes a finality seat");
        let mut restored = honest_validator_set();
        restored.import_finality_state(chain.finality_seats());
        assert_eq!(validator_set_disagreement(&chain, &restored), None, "⛔ an honest restore of the finality seats fired");
        let mut party = honest_validator_set();
        party.import_finality_state(vec![(vid(5), 1_000)]);
        assert_eq!(party.export_state().0, chain.export_state().0, "⛔ only the FINALITY seats may differ here");
        assert_eq!(party.total_finality_weight(), chain.total_finality_weight(), "⛔ the totals must match, or this is the total test");
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `finality_bonds` COMPARISON CANNOT FIRE: a different finality member at the same total was invisible");
        assert!(fired.contains("ValidatorSet::finality_bonds"), "the finding must NAME the finality seats: got {fired}");
    }

    /// ⭐⭐⭐ G2b (2026-10-22) — the view at a height: the same seats ACTIVATING at another height, and an exit that left
    /// a departed row on one side only. Driven through `import_seat_activations`, the real snapshot / bundle restore door.
    /// NEGATIVE CONTROL: an exact round trip is silent; each of the four fields' comparison is proven to fire by name.
    /// ⭐⭐⭐ §BR-3 17.3 / 17.6 — `ValidatorSet::delegated` and `ValidatorSet::own_yield`, EACH PROVEN TO FIRE: a party restored
    /// with a delegated word the chain never wrote, and one with an own-weight yield word the chain never wrote, each through
    /// the REAL snapshot door (`import_seat_words`). NEGATIVE CONTROL: an honest restore of the chain's own words is silent.
    #[test]
    fn validator_seat_word_comparisons_fire_when_a_delegated_or_yield_word_diverges() {
        let chain = honest_validator_set();
        let mut restored = chain.clone();
        restored.import_seat_words(chain.seat_words());
        assert_eq!(validator_set_disagreement(&chain, &restored), None, "⛔ an honest restore of the seat words fired");
        let custody_id = chain.export_state().0[0].0;
        let mut party = chain.clone();
        party.import_seat_words(vec![(custody_id, 1, None, 0)]);
        assert_eq!(party.delegated_to(&custody_id), 1, "⛔ THE VIOLATING STATE WAS NEVER BUILT. Repair the construction.");
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `delegated` COMPARISON CANNOT FIRE: a delegated word the chain never wrote was invisible");
        assert!(fired.contains("ValidatorSet::delegated"), "the finding must NAME the field: got {fired}");
        let mut party = chain.clone();
        party.import_seat_words(vec![(custody_id, 0, Some(5), 7)]);
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `own_yield` COMPARISON CANNOT FIRE: a yield word the chain never wrote was invisible");
        assert!(fired.contains("ValidatorSet::own_yield"), "the finding must NAME the field: got {fired}");
    }

    #[test]
    fn validator_seat_activation_comparisons_fire_when_a_seat_activates_or_departs_at_another_height() {
        let mut chain = honest_validator_set();
        chain.admit_finality_active_from(vid(4), 1_000, 70).expect("v4 takes a finality seat active from 70");
        let mut restored = honest_validator_set();
        restored.import_finality_state(chain.finality_seats());
        let acts = chain.seat_activations();
        restored.import_seat_activations(acts.0.clone(), acts.1.clone(), acts.2.clone(), acts.3.clone());
        assert_eq!(validator_set_disagreement(&chain, &restored), None, "⛔ an honest restore of the activation view fired");
        // finality_active_from: the same seat, active from 0 on the party
        let mut party = restored.clone();
        party.import_seat_activations(acts.0.clone(), vec![(vid(4), 0)], acts.2.clone(), acts.3.clone());
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `finality_active_from` COMPARISON CANNOT FIRE: the same seat active from another height was invisible");
        assert!(fired.contains("ValidatorSet::finality_active_from"), "the finding must NAME the field: got {fired}");
        // bond_active_from: a custody seat active from another height
        let mut party = restored.clone();
        let custody_id = chain.export_state().0[0].0;
        party.import_seat_activations(vec![(custody_id, 64)], acts.1.clone(), acts.2.clone(), acts.3.clone());
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `bond_active_from` COMPARISON CANNOT FIRE: a custody seat active from another height was invisible");
        assert!(fired.contains("ValidatorSet::bond_active_from"), "the finding must NAME the field: got {fired}");
        // departed rows: the chain's exit leaves rows; the party's exit (a fixture's) leaves none
        let mut chain2 = chain.clone();
        chain2.remove_exiting_at(&vid(4), Some(200)).expect("v4 exits at 200");
        let mut party = chain.clone();
        party.remove(&vid(4)).expect("v4 exits at every height");
        let fired = validator_set_disagreement(&chain2, &party)
            .expect("⛔ THE `departed_finality` COMPARISON CANNOT FIRE: a missing departed row was invisible");
        assert!(fired.contains("ValidatorSet::departed_finality"), "the finding must NAME the field: got {fired}");
        let mut chain3 = chain.clone();
        let custody_id = chain3.export_state().0[0].0;
        chain3.remove_exiting_at(&custody_id, Some(200)).expect("a custody seat exits at 200");
        let mut party = chain.clone();
        party.remove(&custody_id).expect("the custody seat exits at every height");
        let fired = validator_set_disagreement(&chain3, &party)
            .expect("⛔ THE `departed_bond` COMPARISON CANNOT FIRE: a missing departed custody row was invisible");
        assert!(fired.contains("ValidatorSet::departed_bond"), "the finding must NAME the field: got {fired}");
    }

    /// ⭐⭐⭐ SATOSHI §6 — `ValidatorSet::total_finality`: the finality DENOMINATOR moved with the seats byte-identical.
    #[test]
    fn validator_total_finality_comparison_fires_when_the_finality_denominator_diverges() {
        let mut chain = honest_validator_set();
        chain.admit_finality(vid(4), 1_000).expect("v4 takes a finality seat");
        let mut party = honest_validator_set();
        party.import_finality_state(chain.finality_seats());
        assert_eq!(validator_set_disagreement(&chain, &party), None, "NEGATIVE CONTROL: the same seats are silent");
        party.force_total_finality_for_selfproof(9_999);
        assert_ne!(party.total_finality_weight(), chain.total_finality_weight(), "⛔ THE VIOLATING STATE WAS NEVER BUILT");
        assert_eq!(party.finality_seats(), chain.finality_seats(), "⛔ only the denominator may move here");
        let fired = validator_set_disagreement(&chain, &party)
            .expect("⛔ THE `total_finality` COMPARISON CANNOT FIRE: a finality denominator its seats do not sum to was invisible");
        assert!(fired.contains("ValidatorSet::total_finality"), "the finding must NAME the finality denominator: got {fired}");
    }

    /// ⭐⭐⭐ `ValidatorSet::total_bond` — THE DENOMINATOR OF EVERY ≥2/3 GATE.
    ///
    /// Finality and the peg both ask `weight * 3 >= 2 * total_bond`. A party holding a SMALLER total
    /// finalises on less than two-thirds of the real bonded weight — it declares irreversible what the
    /// mesh can still reorg — and a party holding a larger one refuses a quorum the mesh accepted. The
    /// membership is byte-identical on both sides, so this is the denominator and nothing else.
    #[test]
    fn validator_total_bond_comparison_fires_when_the_threshold_denominator_diverges() {
        let chain = honest_validator_set();
        let mut party = honest_validator_set();
        assert_eq!(
            validator_set_disagreement(&chain, &party),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST PAIR: two sets admitted the same way are \
             the same set."
        );

        let before = party.total_bond();
        party.force_total_bond_for_selfproof(3_000);
        let after = party.total_bond();
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the bonded weight did not move. Fix the \
             construction, never the assertion."
        );
        assert_eq!(
            party.export_state().0,
            chain.export_state().0,
            "⛔ THE MUTATION MUST MOVE ONLY THE DENOMINATOR — a membership change would make this the \
             `bonds` test again and leave `total_bond` unrefuted."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `total_bond` COMPARISON CANNOT FIRE: the party divides every ≥2/3 gate by a bonded \
             weight its own members do not sum to, and the comparison was silent.",
        );
        assert!(
            fired.contains("ValidatorSet::total_bond"),
            "the finding must NAME the threshold denominator: got {fired}"
        );
    }

    /// `ValidatorSet::slashed` — a slashed id may NEVER re-admit. A party that does not hold the same
    /// barred set will re-seat a proven double-signer, and the economic teeth stop biting. Driven
    /// through `import_state`, the real restore door, with the bonds and the burn figure held equal so
    /// only the barred set differs.
    #[test]
    fn validator_slashed_comparison_fires_when_one_side_bars_a_double_signer_the_other_does_not() {
        let chain = honest_validator_set();
        let (b, s, sb, bc, cu) = chain.export_state();
        let mut party = ValidatorSet::new();
        party.import_state(b.clone(), s.clone(), sb, bc, cu.clone());
        assert_eq!(
            validator_set_disagreement(&chain, &party),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST RESTORE"
        );

        let before = party.export_state().1;
        party.import_state(b, vec![vid(7)], sb, bc, cu);
        let after = party.export_state().1;
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the barred set did not move. Fix the construction, \
             never the assertion."
        );
        assert!(
            party.is_slashed(&vid(7)) && !chain.is_slashed(&vid(7)),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: `vid(7)` must be barred on ONE side only — that \
             asymmetry is a double-signer one node re-seats and the other refuses."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `slashed` COMPARISON CANNOT FIRE: one side permanently bars a proven double-signer \
             the other will happily re-admit, and the comparison was silent.",
        );
        assert!(
            fired.contains("ValidatorSet::slashed"),
            "the finding must NAME the barred set: got {fired}"
        );
    }

    /// `ValidatorSet::slashed_bond_burned` — units that LEFT the bonded weight forever. Supply moves
    /// only via chain objects, so two nodes disagreeing about how much bond was burned disagree about
    /// supply that moved.
    #[test]
    fn validator_slashed_burned_comparison_fires_on_a_burn_figure_no_slash_produced() {
        let chain = honest_validator_set();
        let (b, s, sb, bc, cu) = chain.export_state();
        let mut party = ValidatorSet::new();
        party.import_state(b.clone(), s.clone(), sb, bc, cu.clone());
        assert_eq!(
            validator_set_disagreement(&chain, &party),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST RESTORE"
        );

        let before = party.slashed_bond_burned();
        party.import_state(b, s, sb + 2_000, bc, cu);
        let after = party.slashed_bond_burned();
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the burn figure did not move. Fix the \
             construction, never the assertion."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `slashed_bond_burned` COMPARISON CANNOT FIRE: the two sides disagree about how much \
             bond left the bonded weight forever, and the comparison was silent.",
        );
        assert!(
            fired.contains("ValidatorSet::slashed_bond_burned"),
            "the finding must NAME the burn figure: got {fired}"
        );
    }

    /// `ValidatorSet::bond_commit` — the confidential bonded-stake digest every admit, unbond and slash
    /// is VERIFIED AGAINST (`verify_bond_admit` / `verify_bond_reduce` both close over it). A party
    /// holding a different one accepts conservation proofs the mesh refuses and refuses ones it accepts.
    #[test]
    fn validator_bond_commit_comparison_fires_on_a_digest_no_transition_proved() {
        let chain = honest_validator_set();
        let mut party = honest_validator_set();
        assert_eq!(
            validator_set_disagreement(&chain, &party),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST PAIR"
        );

        let before = party.bond_commit();
        party.apply_bond_transition(usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]));
        let after = party.bond_commit();
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the bonded-stake digest did not move. Fix the \
             construction, never the assertion."
        );
        assert_eq!(
            party.export_state().0,
            chain.export_state().0,
            "⛔ THE MUTATION MUST MOVE ONLY THE DIGEST — a membership change would make this the \
             `bonds` test again."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `bond_commit` COMPARISON CANNOT FIRE: the two sides judge every bond transition \
             against different digests, and the comparison was silent.",
        );
        assert!(
            fired.contains("ValidatorSet::bond_commit"),
            "the finding must NAME the bonded-stake digest: got {fired}"
        );
    }

    /// ⭐⭐⭐ `ValidatorSet::custody` — WHERE A USER'S REAL BTC AND XMR ACTUALLY LAND.
    ///
    /// `bonded_custody()` is the live bonded set's key-aggregate; `Node::reserve_addresses` derives the
    /// deposit addresses from it and `src/rpc_http.rs:3337` serves them to a user about to send real
    /// coin. Two nodes with different custody sets hand that user DIFFERENT addresses, and at most one
    /// is controlled by the quorum — the other is an address nobody can spend from.
    #[test]
    fn validator_custody_comparison_fires_when_the_reserve_aggregate_differs() {
        let chain = honest_validator_set();
        let (b, s, sb, bc, cu) = chain.export_state();
        let mut party = ValidatorSet::new();
        party.import_state(b.clone(), s.clone(), sb, bc, cu.clone());
        assert_eq!(
            validator_set_disagreement(&chain, &party),
            None,
            "⛔ THE VALIDATOR COMPARISON FIRES ON AN HONEST RESTORE"
        );

        let before = party.bonded_custody().len();
        party.import_state(b, s, sb, bc, Vec::new());
        let after = party.bonded_custody().len();
        assert_ne!(
            after, before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the reserve aggregate holds the same number of \
             shares ({before}), so the addresses it derives are unchanged and the assertion below \
             would pass for the wrong reason. Fix the construction, never the assertion."
        );
        assert_eq!(
            party.export_state().0,
            chain.export_state().0,
            "⛔ THE MUTATION MUST MOVE ONLY THE CUSTODY SET — the bonded membership is identical, which \
             is what makes this a reserve-address question rather than a quorum one."
        );

        let fired = validator_set_disagreement(&chain, &party).expect(
            "⛔ THE `custody` COMPARISON CANNOT FIRE: the two sides aggregate different custody shares, \
             so they derive DIFFERENT BTC/XMR reserve deposit addresses for the same swap — and the \
             comparison was silent. A depositing user sends real coin to whichever node they asked.",
        );
        assert!(
            fired.contains("ValidatorSet::custody"),
            "the finding must NAME the custody set: got {fired}"
        );
    }

    /// ⛔⛔ EVERY FIELD A `*_COMPARED` LIST NAMES MUST HAVE A COMPARISON THAT REPORTS IT BY NAME.
    ///
    /// The lists above are the coverage claim; the tests above are the evidence. This binds the two:
    /// each name must appear, spelled `Struct::field`, in the source of the comparison that claims it.
    /// A name added to a list without a comparison reading it would otherwise lower the uncompared
    /// ceiling while protecting nothing — the exact "reads as covered" failure the ceiling exists to
    /// prevent.
    #[test]
    fn every_compared_field_is_named_by_the_comparison_that_claims_it() {
        let src = include_str!("authority_book.rs");
        for (what, list) in [
            ("OrderBook", ORDER_BOOK_COMPARED),
            ("Directory", DIRECTORY_COMPARED),
            ("ValidatorSet", VALIDATOR_SET_COMPARED),
        ] {
            for field in list {
                let spelled = format!("{what}::{field}");
                assert!(
                    src.contains(&spelled),
                    "⛔ `{spelled}` is listed as COMPARED but no comparison in this file names it. \
                     Either the comparison does not read it — in which case the ceiling was lowered \
                     for a field nothing protects — or the finding does not name it, and a reader \
                     chasing a misdirected payment is sent to the wrong subsystem."
                );
            }
        }
    }
}

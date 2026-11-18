// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CROSS-NODE / CROSS-DEVICE TEST STANDARD, ENFORCED BY THE WALLET'S OWN SUITE.
//!
//! The node crate has ratcheted this standard since 2026-07-27 (`usdmd-node/src/test_standard.rs`). The
//! WALLET crate did not, and that gap is exactly where the user-visible failures live: a wallet is the party
//! that DISAGREES with a node, and a wallet test that builds its chain state from one node can never express
//! that.
//!
//! Every expensive failure in this project was a disagreement between two parties:
//!
//!   * a wallet detected a note its own node could not serve   -> balance visible, funds UNSPENDABLE
//!   * a wallet's prefilter dropped its own incoming payment   -> every cross-device send lost
//!   * a wallet built a witness against a root the node moved  -> every send refused, silently
//!   * a wallet read one node's tip and proved against it      -> the gate verified what the node already believed
//!
//! Every one was green under a narrower test. The narrowing IS the defect.
//!
//! ## What this module does
//!
//! [`tests::every_wallet_chain_state_test_has_two_parties`] reads the crate's own source and applies the
//! standard to every `#[test]` in it. A test is IN SCOPE when it BUILDS CHAIN STATE — constructs a `Node`,
//! records a note payload, touches the DA layer, ingests, produces, restores, or drives a live node over
//! HTTP. Pure key/hash/serialization units are legitimately one-party and are not in scope.
//!
//! An in-scope test must involve TWO parties: a second `Node`, a peer ingest, a second wallet, or a second
//! device.
//!
//! ## The ratchet
//!
//! [`LEGACY_ONE_PARTY`] freezes the wallet tests that did not meet the standard when it was introduced. The
//! assertion is two-sided — a NEW single-party chain-state test fails, and a listed test that has since been
//! FIXED fails until its entry is deleted. So the list can only SHRINK, cannot be padded to buy silence, and
//! reaches zero when the wallet fully meets the standard.
//!
//! ([[feedback_cross_device_testing_cardinal]])

/// Wallet tests that BUILD CHAIN STATE with a single party, frozen when this standard reached the wallet
/// crate. Shrink this list by giving a test a second node/wallet/device and asserting the two AGREE.
/// NEVER add to it.
#[cfg(test)]
pub const LEGACY_ONE_PARTY: &[(&str, &str)] = &[
    // ⭐ RATCHETED 7 -> 3 on 2026-09-24. FOUR entries were STALE — those tests had gained a second party
    // at some point and the guard's own ratchet arm had been RED on them, unnoticed, because its other
    // arm was red too and one failure hides another. The list may only shrink, so deleting them is the
    // required move, not a courtesy.
    //
    // ⛔ THE FIFTH deletion is the one that was earned this session:
    // `a_seed_only_restore_costs_the_same_on_a_tall_chain_as_a_short_one` was never on this list — it was
    // a FRESH offender the guard refused outright. Giving it a second party (a node that only INGESTS the
    // carrier block and must still find the owner's note) immediately surfaced a real node defect: the
    // owner's position index carried a FABRICATED SLOT
    // ([[project_fabricated_slot_in_the_position_index]]), which had been breaking live sends since
    // 2026-09-21. That is what this standard is for.
    ("lib.rs", "the_wallet_derives_a_copath_over_real_http_with_no_note_stream"),
];

#[cfg(test)]
mod tests {
    use super::LEGACY_ONE_PARTY;

    /// Does this test build CHAIN STATE (as opposed to being a pure unit)?
    /// Strip `//` comments so classification reads CODE, never prose.
    ///
    /// ⛔ A DOC COMMENT IS NOT CHAIN STATE. Without this, a test whose comment merely EXPLAINS chain
    /// behaviour — "the node must still be able to produce", "one node ingests the other's block" — is
    /// classified as building chain state and demanded a second party it has no use for. That is a false
    /// positive, and false positives are how a standard gets weakened: the pressure becomes to add the test
    /// to the frozen legacy list (which may only shrink) or to reword honest prose until the detector stops
    /// noticing. Reading code makes the guard STRICTER — a real `Node::new` still trips it, and a commented
    /// -out one correctly does not.
    fn code_only(body: &str) -> String {
        let no_comments: String = body
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        // Also drop STRING LITERALS. An assertion MESSAGE that explains chain behaviour — "…tells its node to
        // elect itself an origin", "the node must still be able to produce" — is prose living in quotes, and a
        // test cannot build chain state by naming a function inside a message. A real `node.produce(..)` call
        // is unquoted and still caught.
        let mut out = String::with_capacity(no_comments.len());
        let mut in_str = false;
        let mut escaped = false;
        for c in no_comments.chars() {
            match (in_str, c) {
                (true, '\\') if !escaped => escaped = true,
                (true, '"') if !escaped => in_str = false,
                (true, _) => escaped = false,
                (false, '"') => in_str = true,
                (false, _) => out.push(c),
            }
        }
        out
    }

    fn builds_chain_state(body: &str) -> bool {
        let body = &code_only(body);
        const MARKERS: &[&str] = &[
            "Node::new",
            "record_note_payload",
            "record_account_target",
            "da_store",
            "da_load",
            "da_record",
            "da_block_leaves",
            "da_note_copath",
            "membership_roots_from",
            "ingest_block",
            "apply_block",
            // ⚠️ CALL-SHAPED, not a bare word: "produce" is a substring of "reproduces", so
            // `restore_reproduces_the_exact_wallet` — a pure key-derivation test that touches no chain —
            // was classified as building chain state. A marker that fires on an unrelated English word
            // pushes correct tests toward the frozen legacy list, which is how a standard rots.
            "produce(",
            "graft_mined",
            "instant_sync",
            "run_in_process",
            "spend_frontier_root",
            "account_bucket",
        ];
        MARKERS.iter().any(|m| body.contains(m))
    }

    /// Does the test actually involve a SECOND party?
    fn has_two_parties(body: &str) -> bool {
        let lc = body.to_lowercase();
        const MARKERS: &[&str] = &[
            "node_a", "node_b", "wallet_b", "device_b", "two_nodes", "cross_device", "cross_node",
            "ingest_block", "peer", "from_b", "on_b",
        ];
        if MARKERS.iter().any(|m| lc.contains(m)) {
            return true;
        }
        // BOTH roles, never either alone — a subject merely NAMED "verifier" is still one party.
        if lc.contains("producer") && lc.contains("verifier") {
            return true;
        }
        // Two independent nodes in one body is the plainest two-party shape there is.
        lc.matches("node::new").count() >= 2
    }

    /// Every `#[test] fn name() { .. }` in a source file, with its brace-balanced body.
    fn test_bodies(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let chars: Vec<char> = src.chars().collect();
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("#[test]") {
            let at = from + rel;
            from = at + 7;
            let Some(fpos) = src[at..].find("fn ") else { continue };
            let after = at + fpos + 3;
            let Some(paren) = src[after..].find('(') else { continue };
            let name: String = src[after..after + paren].trim().to_string();
            if name.is_empty() || name.contains(char::is_whitespace) {
                continue;
            }
            let Some(open_rel) = src[after..].find('{') else { continue };
            let open = after + open_rel;
            let start = src[..open].chars().count();
            let mut depth = 0i32;
            let mut end = start;
            for i in start..chars.len() {
                match chars[i] {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let body: String = chars[start..=end].iter().collect();
            out.push((name, body));
        }
        out
    }

    #[test]
    fn every_wallet_chain_state_test_has_two_parties() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("the crate's own source directory is readable")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
            .collect();
        files.sort();
        // A scan that finds nothing passes every assertion below — the exact failure mode this standard
        // exists to prevent, committed by the standard itself.
        assert!(files.len() > 3, "the scan must actually find the crate's sources, found {}", files.len());

        let mut offenders: Vec<(String, String)> = Vec::new();
        let mut scanned = 0usize;
        for path in &files {
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            if file == "test_standard.rs" {
                continue; // this module's own test builds no chain state
            }
            let src = std::fs::read_to_string(path).expect("source file is readable");
            for (name, body) in test_bodies(&src) {
                scanned += 1;
                if builds_chain_state(&body) && !has_two_parties(&body) {
                    offenders.push((file.clone(), name));
                }
            }
        }
        assert!(scanned > 30, "the parser must actually find the suite's tests, found {scanned}");

        let frozen: std::collections::BTreeSet<(String, String)> =
            LEGACY_ONE_PARTY.iter().map(|(f, n)| (f.to_string(), n.to_string())).collect();
        let found: std::collections::BTreeSet<(String, String)> = offenders.iter().cloned().collect();

        // (1) NEW single-party chain-state tests are refused outright.
        let fresh: Vec<_> = found.difference(&frozen).collect();
        assert!(
            fresh.is_empty(),
            "these WALLET tests build chain state with only ONE party. A wallet is the party that DISAGREES \
             with a node — balance visible but unspendable, a prefilter dropping its own payment, a witness \
             built against a root that moved. None of those can appear when the wallet and its node are the \
             same story. Give the test a second `Node` (one PRODUCES, the other INGESTS) or a second wallet, \
             and assert they derive the SAME thing. Offenders: {fresh:#?}"
        );

        // (2) The ratchet: a listed test that now has two parties must be REMOVED from the list, so the
        //     baseline can only shrink and can never be padded to buy silence.
        let stale: Vec<_> = frozen.difference(&found).collect();
        assert!(
            stale.is_empty(),
            "these wallet tests now meet the standard — delete their LEGACY_ONE_PARTY entries so the \
             baseline ratchets down: {stale:#?}"
        );
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `pqauth::af47_pins` — A-F47 pin tests for node-key statement network binding.
//! Kept in the node crate because `pqauth` itself compiles in the ledger crate.
// O1-INFINITY-REVIEWED: this test reads SOURCE FILES for a domain-literal census — no runtime state, no local storage, no per-item growth; the test itself is constant-size regardless of chain height

use crate::pqauth::*;
use crate::hash::Hash32;

/// A-F47 CENSUS — EVERY NODE-KEY STATEMENT NAMES ITS NETWORK, AND EVERY STATEMENT DOMAIN IN THE SOURCE IS NAMED HERE.
#[test]
fn af47_every_node_key_statement_names_its_network_and_every_domain_is_listed() {
    use crate::params::{network_genesis_prefix, process_network_id, set_thread_network_for_test};
    const NODE: &[&str] = &[
        "musdm.finality.vote.v1",
        "musdm.psm.mint.v1",
        "musdm.validator.membership.v2",
        "musdm.peg.in.conf.v4",
        "musdm.wrap.mint.conf.v3",
        "musdm.peg.out.conf.v7",
        "musdm.peg.revalue.v2",
        "musdm.peg.bridge-credit.v2",
        "musdm.peg.wrapped-register.v1",
        "musdm.peg.price-mark.v1",
        "musdm.peg.vault-merge.release.v1",
        "musdm.peg.vault-merge.accept.v1",
        "musdm.peg.vault-rebalance.carve.v1",
        "musdm.peg.vault-rebalance.take.v1",
        "musdm.peg.vault-rebalance.cancel.v1",
        "musdm.peg.vault-rebalance.consent.v1",
        "musdm.peg.vault-key.take.v2",
        "musdm.peg.vault-key.retire.v1",
        "musdm.peg.reserve-cost.v1",
        "musdm.peg.theft-repay.v1",
        "musdm.peg.pot-fill.v1",
        "musdm.peg.unit-close.v1",
        "musdm.peg.pool.release-batch.v1",
        "musdm.peg.decoy-batch.v1",
        "musdm.peg.decoy-return.v1",
        "musdm.custody.share.v1",
        "musdm.validator.instance.v2",
    ];
    const OTHER: &[(&str, &str)] = &[
        ("musdm.site.publish.v1", "wallet key; a site's owner publishes its own manifest root"),
        ("musdm.gov.vote.v1", "wallet key; the proposal id is a chain object of this network"),
        ("musdm.name.register.v1", "wallet key; a name maps to an address whose network the address names"),
        ("musdm.clue.register.v1", "wallet key; the clue key is the wallet's own"),
        ("musdm.dir.register.v1", "wallet key; a directory entry is paid with a note of this network"),
        ("musdm.validator.unbond.v4", "the validator's own key, also from the wallet seed; names the bond instance, which every node derives under its own network id (musdm.validator.instance.v2 is a NODE domain), and a one-shot nonce"),
        ("musdm.validator.bond.v1", "the validator's own key, also from the wallet seed; names the locked note and its nullifier on this chain"),
        ("musdm.validator.seat.v1", "a hash: the seat-right nullifier, never signed"),
        ("musdm.validator.unbond-right.v2", "a hash: the unbond-right nullifier, never signed"),
        ("musdm.spend.statement.v1", "the spend proof's statement domain, built by the wallet prover; a spend is bound to its chain by its stamp (mempool::stamp)"),
        ("musdm.spend.lock.v1", "the spend lock domain, built by the wallet prover; bound to its chain by its stamp"),
    ];
    let under = |net: &str| -> Vec<Vec<u8>> {
        set_thread_network_for_test(&network_genesis_prefix(net));
        let id = *process_network_id().as_bytes();
        let v = vec![
            finality_vote_msg(&Hash32([7u8; 32]), 5),
            mint_attest_msg(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 15_000),
            validator_membership_msg(&[5u8; 32], &[6u8; 32]),
            crate::peg::PegLedger::price_mark_msg(9, 0, 74_282_306_163),
            crate::theft_tx::theft_msg(b"statement", &[[8u8; 32]], 100_000_000),
        ];
        for (m, d) in v.iter().zip(["musdm.finality.vote.v1", "musdm.psm.mint.v1", "musdm.validator.membership.v2", "musdm.peg.price-mark.v1", "USDMD-PQFROST-THEFT-v3"]) {
            assert!(m.starts_with(d.as_bytes()) && m[d.len()..].starts_with(&id), "{d} starts with its domain and the network id");
        }
        v
    };
    let (test, main) = (under("testnet"), under("mainnet"));
    for (t, m) in test.iter().zip(&main) {
        assert_ne!(t, m, "a node-key statement on the testnet is not the same statement on mainnet");
    }
    // source census — reads .rs files at build time, not runtime state
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = if base.join("src/pqauth.rs").exists() { base.join("src") } else { base.join("../src") };
    let mut files = vec![src.clone()];
    const BOUND_BUILDERS: &[&str] = &[
        "finality_vote_msg", "mint_attest_msg", "validator_membership_msg", "price_mark_msg", "wrapped_register_msg",
        "theft_msg", "deal_msg", "signal_msg", "statement",
    ];
    const OTHER_BUILDERS: &[(&str, &str)] = &[
        ("validator_unbond_msg", "see musdm.validator.unbond.v4"),
        ("validator_bond_msg", "see musdm.validator.bond.v1"),
        ("clue_register_msg", "see musdm.clue.register.v1"),
        ("governance_vote_msg", "see musdm.gov.vote.v1"),
        ("name_register_msg", "see musdm.name.register.v1"),
        ("site_publish_msg", "see musdm.site.publish.v1"),
        ("lock_msg", "names the genesis itself (spend_lock::lock_msg)"),
        ("record_msg", "the entry-mix coordinator's record of its own round id; moves no value"),
        ("peer_record_msg", "a transport record of an onion; names no chain and moves no value"),
        ("attestation_msg", "a builder's signature over a release, the same binary on every network; verify-release checks it offline, with no node"),
    ];
    let mut unknown_builders = Vec::new();
    let mut seen_node = std::collections::BTreeSet::new();
    let mut unknown = Vec::new();
    while let Some(dir) = files.pop() {
        for e in std::fs::read_dir(&dir).expect("the node source is readable") {
            let p = e.expect("an entry").path();
            if p.is_dir() {
                files.push(p);
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name.ends_with("_pins.rs") || name.ends_with("_pin.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).expect("a source file"); // O1-INFINITY-REVIEWED: reads source code for static domain-literal census, not runtime state
            if name == "pins.rs" || name == "test_support.rs" || text.lines().take(60).any(|l| l.trim_start().starts_with("#![cfg(") && l.contains("test")) {
                continue;
            }
            let lines: Vec<&str> = text.split_inclusive('\n').collect();
            let mut kept = String::with_capacity(text.len());
            let mut k = 0;
            while k < lines.len() {
                let l = lines[k];
                let next = lines.get(k + 1).map(|n| n.trim_start()).unwrap_or("");
                if l.trim_start().starts_with("#[cfg(") && l.contains("test") && (next.starts_with("mod ") || next.starts_with("pub mod ")) {
                    if next.trim_end().ends_with('{') {
                        k += 2;
                        while k < lines.len() && lines[k].trim_end() != "}" {
                            k += 1;
                        }
                    } else {
                        k += 1;
                    }
                    k += 1;
                    continue;
                }
                kept.push_str(l);
                k += 1;
            }
            let live = kept.as_str();
            for call in ["ml_dsa_sign(&", ".attest(&"] {
                let mut at = 0;
                while let Some(i) = live[at..].find(call) {
                    let start = at + i + call.len();
                    let rest = &live[start..];
                    let path_len = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':')).unwrap_or(0);
                    if rest[path_len..].starts_with('(') && path_len > 0 {
                        let fname = rest[..path_len].rsplit("::").next().unwrap_or("");
                        if !BOUND_BUILDERS.contains(&fname) && !OTHER_BUILDERS.iter().any(|(o, _)| *o == fname) {
                            unknown_builders.push(format!("{}: {fname}", p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
                        }
                    }
                    at = start;
                }
            }
            let mut at = 0;
            while let Some(i) = live[at..].find("b\"musdm.") {
                let start = at + i + 2;
                let end = start + live[start..].find('"').expect("a closed literal");
                let d = &live[start..end];
                if NODE.contains(&d) {
                    assert!(live[..at + i].ends_with("node_statement("), "{name}: the node-key domain {d} is not built through node_statement");
                    seen_node.insert(d.to_string());
                } else if !OTHER.iter().any(|(o, _)| *o == d) {
                    unknown.push(format!("{name}: {d}"));
                }
                at = end;
            }
        }
    }
    assert!(unknown_builders.is_empty(), "statement builders signed in the source and named in neither list: {unknown_builders:?}");
    assert!(unknown.is_empty(), "statement domains named in neither list: {unknown:?}");
    let missing: Vec<_> = NODE.iter().filter(|d| !seen_node.contains(**d)).collect();
    assert!(missing.is_empty(), "NODE domains no longer in the source: {missing:?}");
}

/// A-F47 REFUSAL — ONE HONEST KEY'S VOTE ON ANOTHER NETWORK IS NEVER HALF OF AN EQUIVOCATION HERE.
#[test]
fn af47_a_vote_signed_on_another_network_is_never_half_of_an_equivocation() {
    use crate::params::{network_genesis_prefix, set_thread_network_for_test};
    use crate::validator::VoteCert;
    let (pk, sk) = ml_dsa_keypair();
    let (a, b) = (Hash32([0x0a; 32]), Hash32([0x0b; 32]));
    let vote = |block: Hash32| VoteCert {
        pubkey: pk.clone(),
        block,
        height: 5,
        sig: ml_dsa_sign(&finality_vote_msg(&block, 5), &sk).expect("the vote key signs"),
    };
    set_thread_network_for_test(&network_genesis_prefix("mainnet"));
    let on_mainnet = vote(a);
    set_thread_network_for_test(&network_genesis_prefix("testnet"));
    let on_testnet = vote(b);
    let cross = crate::equivocation_tx::encode(&on_mainnet, &on_testnet).expect("two blocks at one height under one key");
    assert_eq!(
        crate::equivocation_tx::proves_equivocation(&cross, &MlDsaVerifier),
        None,
        "⛔ A-F47: a vote signed on mainnet and one signed on the testnet slashed the honest key on the testnet"
    );
    let here = crate::equivocation_tx::encode(&vote(a), &on_testnet).expect("two blocks at one height under one key");
    assert_eq!(
        crate::equivocation_tx::proves_equivocation(&here, &MlDsaVerifier),
        Some(pubkey_id(&pk)),
        "a real double vote on this network still proves the equivocation"
    );
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE MONEY PATH, end to end, against a REAL running node — the one thing unit tests cannot prove.
//!
//! Two real wallets are created through the same code the app's buttons run. One receives testnet-only
//! test USDm, then SENDS to the other's rotating receive address. The payer reads the locator out of that
//! address and tags the note with it; the node turns the tag into an index entry as the block lands; and
//! the recipient — using only its own secret — asks the index where its note is and gets back the exact
//! block and slot, then opens the note there to prove the index pointed at the real thing.
//!
//! Nothing here prints an address, key, locator or amount: a test log is an observable channel like any
//! other, and the assertions carry the proof without emitting any of it.
//!
//! Run it against a node:
//!   MONEROUSD_NODE_URL=http://127.0.0.1:27790 cargo test --release --test oli_live_send -- --ignored --nocapture

use monerousd_wallet_v2_lib::{harness, oli_client, pq};
use std::time::{Duration, Instant};
use usdmd_node::oli;

fn node_url() -> String {
    std::env::var("MONEROUSD_NODE_URL").expect("set MONEROUSD_NODE_URL to a running testnet node")
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(120)).build()
}

/// Request testnet-only valueless test USDm for `address` from the node's testnet issuance route.
fn request_test_usdm(a: &ureq::Agent, url: &str, address: &str, atomic: u64) -> Result<Vec<u8>, String> {
    let resp: serde_json::Value = a
        .post(&format!("{url}/faucet/drip"))
        .send_json(serde_json::json!({ "to": address, "amount": atomic }))
        .map_err(|e| format!("issuance request: {e}"))?
        .into_json()
        .map_err(|e| format!("issuance json: {e}"))?;
    let status = resp.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status != "OK" {
        return Err(format!("issuance refused: {resp}"));
    }
    let note_hex = resp.get("note").and_then(|n| n.as_str()).ok_or("issuance returned no note")?;
    hex::decode(note_hex).map_err(|e| format!("issued note hex: {e}"))
}

#[test]
#[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE money-path test — it drives an EXTERNAL running node, and FAILS (never skips) once a node is named; the in-suite unit tests cover all node-free ground.
fn a_real_send_tags_the_recipients_note_and_the_recipient_locates_it_from_its_own_secret() {
    let url = node_url();
    let a = agent();
    std::env::set_var("MONEROUSD_NODE_URL", &url);

    // ---- RECIPIENT: a real wallet, and the rotating address it hands the payer. -------------------
    let recipient_seed: serde_json::Value = harness::generate().expect("create recipient wallet");
    let recipient_phrase = recipient_seed["seed"].as_str().expect("seed phrase").to_string();
    let recipient_keys = pq::restore(&recipient_phrase).expect("recipient keys");
    let recv_addr =
        pq::receive_address(&recipient_keys.b, &recipient_keys.scan_ek, &recipient_keys.note_spk, &recipient_keys.loc_sk, 0)
            .expect("recipient rotating address");
    let recv_locator = usdmd_node::address::parse_address_full(&recv_addr)
        .expect("address parses")
        .locator
        .expect("a rotating address carries its locator");
    let _expected_key = oli::index_key(&oli::tag_clue_bytes(&recv_locator));
    println!("[send-test] stage 1/5: recipient wallet ready at receive index 0");

    // ---- PAYER: a second real wallet, holding testnet test USDm. ----------------------------------
    let payer: serde_json::Value = harness::generate().expect("create payer wallet");
    let payer_addr = payer["address"].as_str().expect("payer address").to_string();
    // Sync the payer BEFORE any money arrives. The self-built membership witness aligns to the frontier as
    // of its first refresh and then observes forward contiguously, so a note that lands in the gap between
    // wallet creation and that first refresh is never observed and its copath can never be built. A real
    // wallet is open and syncing before it is paid; mirror that ordering here.
    let _ = harness::balance();
    let issued = request_test_usdm(&a, &url, &payer_addr, 500_000_000).expect("testnet issuance must succeed");
    // Pin WHERE a failure lives: the issued note must open with the payer's own key. If this holds and the
    // balance below still does not move, the fault is in scanning, not in what was sealed.
    let payer_keys = pq::restore(payer["seed"].as_str().expect("payer seed")).expect("payer keys");
    assert!(
        pq::scan_note_full(&issued, &payer_keys.scan_dk, &payer_keys.note_spk).is_some(),
        "the issued note must be sealed to the PAYER's key"
    );

    // Wait (bounded) for that note to become scannable, then send it through the REAL send path.
    let mut spendable = false;
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1000));
        if let Ok(b) = harness::balance() {
            let b: serde_json::Value = b;
            if b.get("atomic").and_then(|v| v.as_u64()).unwrap_or(0) > 0 {
                spendable = true;
                break;
            }
        }
    }
    assert!(spendable, "the issued note must land before it can be sent");
    println!("[send-test] stage 2/5: payer holds a spendable note");

    // The spender proves its note is in the frontier using a copath it builds ITSELF from the observed
    // stream, so the witness book has to catch up to the block holding the note before a spend can be
    // proved. Keep refreshing and retrying, exactly as a user pressing Send would.
    let mut accepted = String::new();
    let mut last_err = String::from("not attempted");
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        let _ = harness::balance();
        match harness::send(&recv_addr, 1.0) {
            Ok(v) => {
                let v: serde_json::Value = v;
                accepted = v.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
                break;
            }
            Err(e) => {
                // A nullifier conflict against a POOLED tx is our OWN earlier submission sitting in the
                // mempool — the send already landed, so stop retrying and go verify it.
                if e.contains("pooled") || e.contains("nullifier conflict") {
                    accepted = "already-pooled".to_string();
                    break;
                }
                last_err = e;
                std::thread::sleep(Duration::from_millis(1500));
            }
        }
    }
    assert!(!accepted.is_empty(), "the real send path must accept: {last_err}");
    println!("[send-test] stage 3/5: node accepted the send: {accepted}");

    // ---- The note must become findable BY LOCATOR, with no scanning. ------------------------------
    // The index rebuilds per epoch rather than per block, so wait (bounded) for the epoch covering it.
    let mut located = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(240);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1000));
        let params = match oli_client::fetch_params(&a, &url) {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Whole shard tables, held fresh for each poll: the index rebuilds per epoch, so a table kept from
        // an earlier poll would be an earlier epoch's (DB-228 — the trivial-PIR locate).
        let mut tables = oli_client::ShardTables::new(
            params.shard_bits,
            *blake3::hash(b"MUSD/oli-live-send/decoy-secret").as_bytes(),
        );
        located = oli_client::locate(&a, &url, &mut tables, &recipient_keys.loc_sk, "recv", 0, 1)
            .expect("the locate path must complete");
        if !located.is_empty() {
            break;
        }
    }

    assert!(
        !located.is_empty(),
        "the recipient must find its note by locator alone — nothing was indexed for it"
    );
    println!("[send-test] stage 4/5: index resolved the locator, with no scan");

    // The located slot must really hold the recipient's note: fetch that block and open the note at that
    // exact slot with the RECIPIENT's key. Without this the index could be pointing anywhere at all.
    // NOT-AN-ADDRESS (DB-223 Q2 §11 (a)): the index names the record by FOLD ORDINAL, so the whole record is fetched
    // by ordinal and the reply names the record address it resolved to.
    let hit = located[0];
    let rec: serde_json::Value = a
        .post(&format!("{url}/da_record"))
        .send_json(serde_json::json!({ "ordinal": hit.ordinal }))
        .expect("fetch the located record by ordinal")
        .into_json()
        .expect("record json");
    assert!(rec["record_addr"].as_u64().is_some(), "the node resolved the located ordinal to a record: {rec}");
    let bytes = hex::decode(rec["notes_hex"].as_str().expect("notes_hex")).expect("record hex");
    assert!(!bytes.is_empty(), "the located record must be served");
    let off = (hit.slot as usize) * pq::PQ_NOTE_BYTES;
    assert!(
        off + pq::PQ_NOTE_BYTES <= bytes.len(),
        "the located slot must lie inside the served block ({} notes served, slot {})",
        bytes.len() / pq::PQ_NOTE_BYTES,
        hit.slot
    );
    let note = &bytes[off..off + pq::PQ_NOTE_BYTES];
    let opened = pq::scan_note_full(note, &recipient_keys.scan_dk, &recipient_keys.note_spk);
    assert!(opened.is_some(), "the located position must open with the RECIPIENT's own key");
    let (value, _seed) = opened.expect("opened above");
    assert_eq!(value, 100_000_000, "and match what was transferred");
    println!("[send-test] stage 5/5: located position verified end to end");
}

/// DIAGNOSTIC (race-free): fold the node's OWN served stream with the plain node math and compare against
/// the A_tip carried BY THE FINAL PAGE — one instant, no second RPC to race. This is the send path's exact
/// comparison with the carrier swapped for raw math, so it isolates stream-vs-carrier at scale.
#[test]
#[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE diagnostic against an EXTERNAL node; fails loudly once a node is named.
fn the_live_fold_stream_reproduces_the_nodes_a_tip() {
    use usdm_decider::nf_sparse_air::{nf_unspent_step_new_acc, sparse_fold_digest_nfs};
    let url = node_url();
    let a = agent();
    // Seed at the node's CERTIFIED BASE — a jumped node never folded the history behind it.
    let seed: serde_json::Value = a
        .post(&format!("{url}/get_nf_fold_inputs"))
        .send_json(serde_json::json!({ "from": 0, "count": 1 }))
        .unwrap()
        .into_json()
        .unwrap();
    let ba: Vec<u64> = seed["base_acc"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    // Same width rule as `bp`/`acc_after` below: the digest is `[u64; DIGEST_LANES]`, never four literals.
    let mut acc: usdmd_node::spend_frontier::Digest4 =
        core::array::from_fn(|i| ba.get(i).copied().unwrap_or(0));
    let mut from = seed["base_seq"].as_u64().unwrap();
    println!("[fold-diag] seeding at base_seq={from}");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        assert!(Instant::now() < deadline, "raw fold could not catch up within the window");
        let page: serde_json::Value = a
            .post(&format!("{url}/get_nf_fold_inputs"))
            .send_json(serde_json::json!({ "from": from, "count": 64 }))
            .unwrap()
            .into_json()
            .unwrap();
        let pa: Vec<u64> = page["a_tip"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        let page_a_tip: usdmd_node::spend_frontier::Digest4 =
            core::array::from_fn(|i| pa.get(i).copied().unwrap_or(0));
        let blocks = page["blocks"].as_array().cloned().unwrap_or_default();
        if blocks.is_empty() {
            if acc == page_a_tip {
                println!("[fold-diag] RAW fold MATCHES A_tip after {from} blocks");
                return;
            }
            println!("[fold-diag] at {from} blocks raw={acc:?} page_a_tip={page_a_tip:?}");
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        for b in &blocks {
            let bp: Vec<u64> = b["block_pre"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
            // ⛔ BUILD THE DIGEST AT ITS OWN WIDTH, NEVER FOUR LITERALS. The digest is
            // `[u64; DIGEST_LANES]` with DIGEST_LANES = 8 (§AG widened it); spelling four indices here
            // stopped this test compiling, and a test that does not compile takes `cargo test` down with
            // it — every wallet pin became unrunnable by the default command. Same class as the
            // 2026-09-24 roots-run decoder (a 4-limb length check against an 8-lane digest).
            let bp: usdmd_node::spend_frontier::Digest4 =
                core::array::from_fn(|i| bp.get(i).copied().unwrap_or(0));
            let raw = hex::decode(b["tags_hex"].as_str().unwrap()).unwrap();
            let tags: Vec<[u8; 32]> = raw
                .chunks_exact(32)
                .map(|c| {
                    let mut t = [0u8; 32];
                    t.copy_from_slice(c);
                    t
                })
                .collect();
            acc = nf_unspent_step_new_acc(acc, bp, sparse_fold_digest_nfs(&tags, bp));
            // PER-BLOCK: the node records the accumulator it reached after folding this very block, so a
            // divergence names the exact block instead of surfacing as one wrong number at the tip.
            let aa: Vec<u64> = b["acc_after"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
            let acc_after: usdmd_node::spend_frontier::Digest4 =
                core::array::from_fn(|i| aa.get(i).copied().unwrap_or(0));
            assert_eq!(
                acc, acc_after,
                "FIRST DIVERGENCE at seq {} (block_pre={:?}, tags={})",
                b["seq"], bp, tags.len()
            );
            from += 1;
        }
    }
}

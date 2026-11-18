// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ R7 LAYER 2 — THE SHIPPED WALLET UI AGAINST A SIMULATED MESH. The wallet tree's `ui-harness` binary (built with
//! `--features ui-harness`) drives the shipped front end headless through one flow of `ui-pins/driver.mjs`, with the real
//! core talking to a simulated node's PRODUCTION RPC and every value-moving command RUN. The simulator keeps the mesh running
//! while the flow works (as it does for `wallet-harness`), reacts to the flow's live events (fund the address it reports),
//! and asserts the flow's effect on the PEER node — never what a call returned to the page.

use super::netsim::{NetSim, Physics};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

/// The `ui-harness` binary: `MONEROUSD_UI_HARNESS_BIN`, else the wallet tree's pin build.
fn ui_harness_bin() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("MONEROUSD_UI_HARNESS_BIN") {
        return p.into();
    }
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("monerousd-wallet-v2/src-tauri/target/pin/ui-harness");
    p
}

/// One live UI flow process: every JSON line it prints arrives on `rx` (live events, core answers, then the verdict).
struct UiProc {
    child: Child,
    rx: mpsc::Receiver<serde_json::Value>,
}

impl UiProc {
    fn start(flow: &str, node_url: &str, args: &serde_json::Value) -> Result<Self, String> {
        let bin = ui_harness_bin();
        if !bin.exists() {
            return Err(format!(
                "the ui-harness is not built at {} — build it with `cargo build --profile pin --features ui-harness --bin ui-harness` \
                 in monerousd-wallet-v2/src-tauri (or name it in MONEROUSD_UI_HARNESS_BIN)",
                bin.display()
            ));
        }
        let mut child = Command::new(bin)
            .args(["--flow", flow, "--node", node_url])
            .env("UI_PIN_ARGS", args.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("the ui-harness did not start: {e}"))?;
        let out = child.stdout.take().ok_or("no stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    let _ = tx.send(v);
                }
            }
        });
        Ok(Self { child, rx })
    }

    fn exited(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_some()
    }
}

/// ⭐⭐ R7 F5 — SEND FROM THE SHIPPED WALLET, AND THE PEER NODE HOLDS IT. A new wallet in the shipped UI reports its address;
/// the faucet funds it through node 0's production RPC; the home screen shows the credit; the user pays 3 USDm through the
/// Send screen's one dollar confirmation; the core's real answer names the recipient's note, and node 1 — fed only by the
/// mesh — holds that note's record. Fails (never skips) when the ui-harness is not built.
/// TWO-PARTY-REVIEWED: the payment is asserted on the PEER node, through the simulated wire.
#[test]
fn sim_ui_send_from_the_shipped_wallet_lands_on_the_peer() {
    let mut sim = NetSim::testnet(2, Physics::from_env(), 11);
    let mut t = 0u64;
    while !sim.one_chain_between(0, 1) && t < 120_000 {
        sim.run(500, 10_000);
        t += 500;
    }
    assert!(sim.one_chain_between(0, 1), "PRECONDITION: one chain");
    let url0 = sim.serve_rpc(0);
    let (ek, _dk) = crate::pqkem::keypair();
    let spk = crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(0x5e)).unwrap();
    let to = crate::harness::real_node_journey::journey_receive_address(0x5e5e, &ek, &spk);
    let args = serde_json::json!({ "to": to, "amount": 3, "wait_ms": 900_000 });
    let mut ui = UiProc::start("live_send", &url0, &args).unwrap_or_else(|e| panic!("⛔ R7 F5: {e}"));
    let (mut funded, mut recipient_cm, mut verdict) = (false, None::<[u8; 32]>, None::<serde_json::Value>);
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < 1_500 {
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let Some(addr) = v.get("address").and_then(|a| a.as_str()) {
                        let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
                        assert_eq!(code, 200, "the faucet funds the shipped wallet: {body}");
                        funded = true;
                    }
                }
                Some("core") if v.get("cmd").and_then(|c| c.as_str()) == Some("wallet_send") => {
                    recipient_cm = v["value"]["recipient_cm"]
                        .as_str()
                        .and_then(|h| crate::rpc_http::hex_decode(h))
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                }
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(500, 10_000);
    }
    let verdict = verdict.unwrap_or_else(|| panic!("⛔ R7 F5: the shipped send flow did not finish (funded {funded})"));
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F5: the shipped send flow failed: {verdict}");
    let cm = recipient_cm.unwrap_or_else(|| panic!("⛔ R7 F5: the core never answered the send with a recipient note: {verdict}"));
    let mut held = false;
    for _ in 0..240 {
        if sim.rt(1).node().holds_record_with_cm(&cm) {
            held = true;
            break;
        }
        sim.run(500, 10_000);
    }
    assert!(held, "⛔ R7 F5: the peer node does not hold the payment the shipped wallet sent");
}

/// Run one live UI flow to its end while the mesh keeps running; `on_emit` handles each live event (e.g. fund an address).
/// Returns `(verdict, every core answer)`. Panics (never skips) when the flow does not finish within `wall_s`.
fn run_ui(sim: &mut NetSim, flow: &str, node: usize, args: serde_json::Value, wall_s: u64, mut on_emit: impl FnMut(&mut NetSim, &serde_json::Value)) -> (serde_json::Value, Vec<serde_json::Value>) {
    let url = sim.serve_rpc(node);
    let mut ui = UiProc::start(flow, &url, &args).unwrap_or_else(|e| panic!("⛔ R7 layer 2 ({flow}): {e}"));
    let (mut verdict, mut core) = (None::<serde_json::Value>, Vec::new());
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < wall_s {
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => on_emit(sim, &v),
                Some("core") => core.push(v),
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(500, 10_000);
    }
    (verdict.unwrap_or_else(|| panic!("⛔ R7 layer 2: the {flow} flow did not finish within {wall_s} s of wall")), core)
}

/// ⭐⭐ R7 F2 — RESTORE FROM THE 24 WORDS: BALANCE AND HISTORY COME BACK. A new wallet in the shipped UI shows its 24 words
/// and is funded through node 0; a FRESH install (another process, empty data) restores those words: home opens in under
/// 1 s, the same address returns, the balance comes back and the history lists the credit — read from the chain through node
/// 1, which was fed only by the mesh.
#[test]
fn sim_ui_restore_from_the_24_words_brings_back_the_balance_and_the_history() {
    let mut sim = NetSim::testnet(2, Physics::from_env(), 13);
    let mut t = 0u64;
    while !sim.one_chain_between(0, 1) && t < 120_000 {
        sim.run(500, 10_000);
        t += 500;
    }
    assert!(sim.one_chain_between(0, 1), "PRECONDITION: one chain");
    let mut reported: Option<(String, String)> = None;
    let (v1, _) = run_ui(&mut sim, "live_fund_report", 0, serde_json::json!({ "wait_ms": 900_000 }), 1_500, |sim, v| {
        if let (Some(addr), Some(phrase)) = (v.get("address").and_then(|a| a.as_str()), v.get("phrase").and_then(|p| p.as_str())) {
            let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
            assert_eq!(code, 200, "the faucet funds the shipped wallet: {body}");
            reported = Some((addr.to_string(), phrase.to_string()));
        }
    });
    assert_eq!(v1["ok"], serde_json::json!(true), "⛔ R7 F2: the funding flow failed: {v1}");
    let (address, phrase) = reported.expect("the flow reported its address and words");
    let (v2, _) = run_ui(&mut sim, "live_restore", 1, serde_json::json!({ "phrase": phrase, "address": address, "wait_ms": 900_000 }), 1_500, |_, _| {});
    assert_eq!(v2["ok"], serde_json::json!(true), "⛔ R7 F2: the restore flow failed: {v2}");
}

/// The BTC price every simulated validator quotes in these flows ($60,000: one satoshi is 60,000 USDm atomic).
const SIM_BTC_PRICE: u128 = 60_000 * crate::liquidation::PRICE_SCALE;

/// The simulated price relays (§21): each serves its own network's body at the simulation's prices ($60,000 per BTC, $150 per
/// XMR), stamped with the simulated clock — what Bisq's and Haveno's pricenodes serve, read by the production parser.
fn sim_relay(i: usize, now_ms: u64) -> Option<Vec<u8>> {
    Some(crate::price_relay::sim_body(i, (SIM_BTC_PRICE / crate::liquidation::PRICE_SCALE) as f64, 150.0, now_ms))
}

/// Each simulated validator's price source: the simulated relays, sampled and read as a real validator samples the onion relays.
fn price_source(sim: &mut NetSim) {
    for i in 0..2 {
        sim.rt(i).set_sim_relays(sim_relay);
    }
}

/// PRECONDITION for a priced flow: the chain has published its Bitcoin mark (the wallet's quote reads the chain's mark, never a
/// third party, so a flow driven before it shows "unavailable" and opens no confirmation).
fn bitcoin_priced(sim: &mut NetSim) {
    let mut t = 0u64;
    while (0..2).any(|i| sim.rt(i).node().price_mark_for(crate::peg::NATIVE_PEG_ASSET_ID).is_none()) && t < 900_000 {
        sim.run(1_000, 10_000);
        t += 1_000;
    }
    assert!((0..2).all(|i| sim.rt(i).node().price_mark_for(crate::peg::NATIVE_PEG_ASSET_ID).is_some()), "PRECONDITION: both nodes hold the chain's Bitcoin mark");
}

fn one_chain_with_custody(sim: &mut NetSim) {
    let mut t = 0u64;
    while !(sim.one_chain_between(0, 1) && (0..2).all(|i| sim.rt(i).node().validators().bonded_ids().len() == 2)) && t < 600_000 {
        sim.run(1_000, 10_000);
        t += 1_000;
    }
    assert!(sim.one_chain_between(0, 1), "PRECONDITION: one chain");
    assert_eq!(sim.rt(0).node().validators().bonded_ids().len(), 2, "PRECONDITION: both daemons hold their seats");
}

/// ⭐⭐ R7 F6 — CASH OUT TO BITCOIN FROM THE SHIPPED WALLET, AND THE PEER HOLDS EVERY STAGED PIECE. A funded wallet in the
/// shipped UI opens Cash out: the privacy delay is on by default and both the quote and the one dollar confirmation say so;
/// Cancel sends nothing; with Auto-OPSEC off both say "next batch, less private"; back on, confirming STAGES the dollar pieces
/// (§19.4: an ordinary payment of each rung to the wallet's own one-time key, then its anonymous claim) and the screen shows
/// the plan's progress. The core's real answer names each piece's staged note, and node 1 — fed only by the mesh — holds
/// every one. Fails (never skips) when the ui-harness is not built.
/// TWO-PARTY-REVIEWED: the staged notes are asserted on the PEER node, through the simulated wire.
/// ⭐⭐ R7 A2/A3 DRIVEN ON A PRICED CHAIN — sell, SAT send, bond and unbond pressed on the shipped UI as a user presses them,
/// against a simulated node that publishes the chain's marks. Every press opens the ONE confirmation before the core is
/// asked; it shows the dollars and a warning; Cancel and Escape ask the core for nothing; Confirm reaches it once.
/// WHY HERE (2026-11-03): the wallet-crate pin drove this flow with NO node, and the Sell quote reads the chain's mark from
/// the node, so the press correctly refused to show dollars it does not have and every later step cascaded red
/// (`price marks: … Connection refused`). A dollar figure needs a priced chain; the claim is measured where one exists.
/// TWO-PARTY-REVIEWED: the UI drives a real wallet core against node 0 of a two-node simulated mesh.
#[test]
fn sim_ui_every_value_moving_press_shows_its_dollars_and_warning_before_the_core_is_asked() {
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let seed = 0xA2A3_2026_1103u64;
    let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_sim_bitcoin(seed, 60_000).boot_from_disk();
    price_source(&mut sim);
    one_chain_with_custody(&mut sim);
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    bitcoin_priced(&mut sim);
    // the flow sells 5 USDm for XMR: the chain's Monero mark must be published too
    let mut t = 0u64;
    while (0..2).any(|i| sim.rt(i).node().price_mark_for(crate::peg::XMR_PEG_ASSET_ID).is_none()) && t < 900_000 {
        sim.run(1_000, 10_000);
        t += 1_000;
    }
    assert!((0..2).all(|i| sim.rt(i).node().price_mark_for(crate::peg::XMR_PEG_ASSET_ID).is_some()), "PRECONDITION: both nodes hold the chain's Monero mark");
    let (verdict, _core) = run_ui(&mut sim, "value_moving_presses", 0, serde_json::json!({ "priced": true }), 1_800, |_, _| {});
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 A2/A3: a value-moving press on the shipped UI failed: {verdict}");
    let invoked: Vec<String> = verdict["invoked"].as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect()).unwrap_or_default();
    for cmd in ["wallet_cash_out", "wallet_send_sat", "wallet_bond_sat"] {
        assert_eq!(invoked.iter().filter(|c| *c == cmd).count(), 1, "{cmd} reached the core once, after its Confirm: {invoked:?}");
    }
    assert!(!invoked.iter().any(|c| c == "wallet_unbond"), "Escape asked the core for nothing: {invoked:?}");
}

#[test]
fn sim_ui_cash_out_from_the_shipped_wallet_stages_every_piece_on_the_peer() {
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let seed = 0xF6_2026_1029u64;
    let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_sim_bitcoin(seed, 60_000).boot_from_disk();
    price_source(&mut sim);
    one_chain_with_custody(&mut sim);
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    bitcoin_priced(&mut sim);
    let (verdict, core) = run_ui(&mut sim, "live_cash_out", 0, serde_json::json!({ "amount": 20, "wait_ms": 900_000, "quote_ms": 600_000, "burn_ms": 900_000 }), 2_400, |sim, v| {
        if let Some(addr) = v.get("address").and_then(|a| a.as_str()) {
            let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
            assert_eq!(code, 200, "the faucet funds the shipped wallet: {body}");
        }
    });
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F6: the shipped cash-out flow failed: {verdict}");
    let answer = core.iter().find(|v| v["cmd"] == "wallet_cash_out").unwrap_or_else(|| panic!("⛔ R7 F6: the cash-out never reached the core: {verdict}"));
    let cms: Vec<[u8; 32]> = answer["value"]["pieces"]
        .as_array()
        .map(|a| a.iter().filter_map(|p| p["escrow_cm_hex"].as_str()).filter_map(crate::rpc_http::hex_decode).filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).collect())
        .unwrap_or_default();
    assert!(!cms.is_empty(), "⛔ R7 F6: the core's answer names no staged piece: {answer}");
    let mut held = vec![false; cms.len()];
    for _ in 0..240 {
        for (i, cm) in cms.iter().enumerate() {
            held[i] |= sim.rt(1).node().holds_record_with_cm(cm);
        }
        if held.iter().all(|h| *h) {
            break;
        }
        sim.run(500, 10_000);
    }
    assert!(held.iter().all(|h| *h), "⛔ R7 F6: the peer does not hold every staged piece: {held:?}");
}

/// ⭐⭐ R7 F4 — ADD MONEY WITH BITCOIN, PRIVATELY, FROM THE SHIPPED WALLET, AND THE PEER SERVES THE BALANCE. The shipped UI
/// (Auto-OPSEC on by default) shows one vault address after its dollar confirmation; the simulator funds it on simulated
/// Bitcoin while three other people mix beside it (users split across both nodes); the wallet mixes, deposits each private
/// unit and the USDm arrives on its home screen; then a FRESH install restores the same words through node 1 — fed only by the
/// mesh — and the balance comes back. Fails (never skips) when the ui-harness is not built.
/// TWO-PARTY-REVIEWED: the balance is read back through the PEER node by another process.
#[test]
fn sim_ui_add_money_with_bitcoin_mixes_mints_and_the_peer_serves_the_balance() {
    use crate::entry_mix as em;
    use crate::harness::mix_journey::{step, vault, User};
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let seed = 0xF4_2026_1029u64;
    let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_sim_bitcoin(seed, 60_000).boot_from_disk();
    price_source(&mut sim);
    one_chain_with_custody(&mut sim);
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    bitcoin_priced(&mut sim);
    let denom = 100_000u64;
    let mut others: Vec<User> = (0..3)
        .map(|i| {
            let (secret, _, addr) = vault("f4-coin", i);
            let txid = sim.btc().fund(&addr, denom + 40_000).expect("funded");
            sim.btc().mine(1);
            let (_, out_spk, out_addr) = vault("f4-out", i);
            let (_, change_spk, _) = vault("f4-change", i);
            User { node: i % 2, secret, coin: (txid, 0, denom + 40_000), cred: em::Credential::fresh().expect("entropy"), out_spk, out_addr, change_spk, stage: 0, hash: String::new(), terms: None, epoch: 0 }
        })
        .collect();
    let mut reported: Option<(String, String)> = None;
    let url = sim.serve_rpc(0);
    let mut ui = UiProc::start("live_add_btc", &url, &serde_json::json!({ "btc": 0.0014, "wait_ms": 1_800_000 })).unwrap_or_else(|e| panic!("⛔ R7 F4: {e}"));
    let mut verdict = None::<serde_json::Value>;
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < 3_000 {
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let (Some(btc), Some(addr), Some(phrase)) = (v["btc_address"].as_str(), v["address"].as_str(), v["phrase"].as_str()) {
                        sim.btc().fund(btc, denom + 40_000).expect("the user's Bitcoin reaches the vault address");
                        sim.btc().mine(1);
                        reported = Some((addr.to_string(), phrase.to_string()));
                    }
                }
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(2_000, 10_000);
        if reported.is_some() {
            for u in others.iter_mut() {
                step(&sim, u, denom);
            }
        }
    }
    let verdict = verdict.unwrap_or_else(|| panic!("⛔ R7 F4: the shipped add-money flow did not finish (stages {:?})", others.iter().map(|u| u.stage).collect::<Vec<_>>()));
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F4: the shipped add-money flow failed: {verdict}");
    let (address, phrase) = reported.expect("the flow reported its addresses and words");
    let (v2, _) = run_ui(&mut sim, "live_restore", 1, serde_json::json!({ "phrase": phrase, "address": address, "wait_ms": 900_000 }), 1_500, |_, _| {});
    assert_eq!(v2["ok"], serde_json::json!(true), "⛔ R7 F4: the peer did not serve the minted balance to a fresh restore: {v2}");
}

/// ⭐⭐ R7 F11 — A USERNAME, A PROFILE AND A PRIVATE LETTER, FROM THE SHIPPED WALLET TO ANOTHER WALLET ON THE OTHER NODE. A
/// receiver wallet (UI on node 1) reports its address; a sender wallet (UI on node 0) claims @ada on the Pay screen through
/// its one dollar confirmation, publishes a profile and sends a sealed letter to the receiver. Asserted on node 1 — fed only
/// by the mesh — and on the receiver's own inbox read through node 1: the name resolves to the sender's address, the
/// profile is served, the letter arrives from the sender with its text. Fails (never skips) when the ui-harness is not built.
/// TWO-PARTY-REVIEWED: two wallets in two processes on two nodes; every assertion reads the OTHER side.
#[test]
fn sim_ui_a_username_a_profile_and_a_private_letter_reach_the_other_node() {
    let mut sim = NetSim::testnet(2, Physics::from_env(), 0xF11_2026);
    let mut t = 0u64;
    while !sim.one_chain_between(0, 1) && t < 120_000 {
        sim.run(500, 10_000);
        t += 500;
    }
    assert!(sim.one_chain_between(0, 1), "PRECONDITION: one chain");
    let (url0, url1) = (sim.serve_rpc(0), sim.serve_rpc(1));
    let mut receiver_ui = UiProc::start("live_letter_receiver", &url1, &serde_json::json!({ "wait_ms": 1_200_000 }))
        .unwrap_or_else(|e| panic!("⛔ R7 F11: {e}"));
    let mut sender_ui: Option<UiProc> = None;
    let (mut receiver, mut sender) = (None::<String>, None::<String>);
    let (mut v_recv, mut v_send) = (None::<serde_json::Value>, None::<serde_json::Value>);
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < 2_400 && (v_recv.is_none() || v_send.is_none()) {
        while let Ok(v) = receiver_ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let Some(addr) = v["receiver"].as_str() {
                        receiver = Some(addr.to_string());
                        sender_ui = Some(
                            UiProc::start("live_names_and_letter", &url0, &serde_json::json!({ "to": addr, "name": "ada" }))
                                .unwrap_or_else(|e| panic!("⛔ R7 F11: {e}")),
                        );
                    }
                }
                _ if v.get("ok").is_some() => v_recv = Some(v),
                _ => {}
            }
        }
        if let Some(ui) = sender_ui.as_mut() {
            while let Ok(v) = ui.rx.try_recv() {
                match v.get("t").and_then(|x| x.as_str()) {
                    Some("emit") => sender = v["sender"].as_str().map(str::to_string),
                    _ if v.get("ok").is_some() => v_send = Some(v),
                    _ => {}
                }
            }
        }
        sim.run(500, 10_000);
    }
    let v_send = v_send.unwrap_or_else(|| panic!("⛔ R7 F11: the sender flow did not finish (receiver {receiver:?})"));
    assert_eq!(v_send["ok"], serde_json::json!(true), "⛔ R7 F11: the sender flow failed: {v_send}");
    let v_recv = v_recv.unwrap_or_else(|| panic!("⛔ R7 F11: the receiver flow did not finish"));
    assert_eq!(v_recv["ok"], serde_json::json!(true), "⛔ R7 F11: the receiver flow failed: {v_recv}");
    let _sender = sender.expect("the sender reported its address");
    // a @username binds the wallet's LOCATOR-FREE handle address (never its rotating receive address): the peer resolves @ada to
    // an address, and the profile signed for THAT address is the sender's ("Ada") — only the holder of its key can publish it
    // the registration and the signed profile reach the peer only through the blocks that carry them: run the mesh until the
    // peer resolves @ada AND serves that address's profile (a bound in SIMULATED time — two minutes of blocks — after which the
    // failure is real)
    let read = |sim: &NetSim| -> (Option<String>, String) {
        let (_, body) = sim.rpc(1, "POST", "/resolve_username", r#"{"name":"ada"}"#);
        let addr = serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|j| j["address"].as_str().map(str::to_string));
        let profile = match &addr {
            Some(a) => sim.rpc(1, "POST", "/dir/profile", &format!(r#"{{"address":"{a}"}}"#)).1,
            None => body,
        };
        (addr, profile)
    };
    let mut t = 0u64;
    let (mut resolved, mut profile) = read(&sim);
    while !(resolved.is_some() && profile.contains("Ada")) && t < 120_000 {
        sim.run(1_000, 10_000);
        t += 1_000;
        (resolved, profile) = read(&sim);
    }
    assert!(resolved.is_some(), "⛔ R7 F11: the peer does not resolve @ada after two minutes of blocks: {profile}");
    assert!(profile.contains("Ada"), "⛔ R7 F11: the address @ada resolves to on the peer does not carry the sender's profile: {profile}");
    assert_eq!(v_recv["letter_msg"], serde_json::json!("hello from the shipped wallet"), "⛔ R7 F11: the letter's text did not arrive: {v_recv}");
}

/// ⭐⭐ R7 F8 + ADOPTABLE A4 — BORROW USDm AGAINST BITCOIN FROM THE SHIPPED WALLET, THEN REPAY IT. The shipped Borrow page (on
/// node 0) offers sizes and safety bands priced at the chain's Bitcoin mark; the confirmation names the liquidation price and
/// that the Bitcoin is not returned if it is liquidated; the deposit address appears and the simulator funds it on simulated
/// Bitcoin; custody mints the unit on both nodes; the loan shows what it owes and how far Bitcoin is from its liquidation
/// price; Repay burns the debt and the unit note and the close lands. Asserted on the PEER (node 1, fed only by the mesh):
/// the unit opened and then closed, and both nodes agree on the supply. Fails (never skips) when the ui-harness is not built.
/// TWO-PARTY-REVIEWED: the executor's node and its peer.
#[test]
fn sim_ui_borrow_against_bitcoin_and_repay_from_the_shipped_wallet_closes_the_unit_on_the_peer() {
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let seed = 0xF8_2026_1029u64;
    let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_sim_bitcoin(seed, 60_000).boot_from_disk();
    price_source(&mut sim);
    one_chain_with_custody(&mut sim);
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    bitcoin_priced(&mut sim);
    let payout = "bcrt1qborrowpayout000000000000000000000000";
    let (verdict, core) = run_ui(&mut sim, "live_borrow", 0, serde_json::json!({ "payout": payout, "wait_ms": 1_500_000, "quote_ms": 300_000 }), 2_700, |sim, v| {
        if let Some(addr) = v.get("address").and_then(|a| a.as_str()) {
            let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
            assert_eq!(code, 200, "the faucet funds the shipped wallet (its repayment note): {body}");
        }
        if let (Some(btc_addr), Some(btc)) = (v.get("btc_address").and_then(|a| a.as_str()), v.get("btc").and_then(serde_json::Value::as_f64)) {
            let sats = (btc * 1e8).round() as u64;
            sim.btc().fund(btc_addr, sats).expect("the borrower's Bitcoin reaches the deposit address");
            sim.btc().mine(6);
        }
    });
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F8: the shipped borrow flow failed: {verdict}");
    assert!(core.iter().any(|v| v["cmd"] == "wallet_borrow_close" && v["value"]["relayed"] == serde_json::json!(true)), "⛔ R7 F8: the repayment never reached the node: {verdict}");
    // the unit OPENED on the peer (its deposit's base id is spent there — one deposit, one unit) and then CLOSED (its cell empty)
    let opened = core.iter().find(|v| v["cmd"] == "wallet_borrow_open").unwrap_or_else(|| panic!("⛔ R7 F8: the loan never reached the core: {verdict}"));
    let deposit = opened["value"]["deposit_address"].as_str().unwrap_or_else(|| panic!("⛔ R7 F8: the open named no deposit address: {opened}"));
    let base = crate::peg::deposit_id_for_reserve_address(deposit);
    let mut t = 0u64;
    let open_total = |sim: &NetSim, i: usize| sim.rt(i).node().peg().unit_book().open.iter().sum::<u64>();
    let settled = |sim: &NetSim| {
        sim.rt(1).node().peg().deposit_minted(&base) && open_total(sim, 1) == 0 && sim.rt(0).node().peg().minted_commit() == sim.rt(1).node().peg().minted_commit()
    };
    while t < 600_000 && !settled(&sim) {
        sim.run(1_000, 10_000);
        t += 1_000;
    }
    assert!(sim.rt(1).node().peg().deposit_minted(&base), "⛔ R7 F8: the unit never opened on the peer");
    assert_eq!(open_total(&sim, 1), 0, "⛔ R7 F8: the peer still holds the unit open after the repayment");
    assert_eq!(sim.rt(0).node().peg().minted_commit(), sim.rt(1).node().peg().minted_commit(), "⛔ R7 F8: the two nodes disagree on the supply after the close");
}


/// Run one `wallet-harness` command batch on another thread while the simulated mesh keeps running (a wallet's refresh needs
/// the node it asks to make progress under it — MEASURED 2026-11-01, h6-pins.log: a payer's faucet credit "never became
/// spendable (0 atomic)" because the test thread blocked in `run()` and no block was produced while it waited).
fn run_meshing(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, cmds: &[&str]) -> Result<Vec<String>, String> {
    let h = w.clone_handle();
    let owned: Vec<String> = cmds.iter().map(|c| c.to_string()).collect();
    let t = std::thread::spawn(move || {
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        h.run(&refs)
    });
    while !t.is_finished() {
        sim.run(500, 10_000);
    }
    t.join().unwrap_or_else(|_| Err("the wallet thread panicked".to_string()))
}

/// `pay_in_session` on another thread while the mesh runs (the same reason as [`run_meshing`]).
fn pay_meshing(sim: &mut NetSim, w: &crate::harness::real_node_journey::wallet::RealWallet, cmd: &str, op: &str, secs: u64) -> (bool, f64, String) {
    let h = w.clone_handle();
    let (cmd, op) = (cmd.to_string(), op.to_string());
    let t = std::thread::spawn(move || h.pay_in_session(&cmd, &op, secs));
    while !t.is_finished() {
        sim.run(500, 10_000);
    }
    t.join().unwrap_or_else(|_| (false, 0.0, "the wallet thread panicked".to_string()))
}

/// Lower-case hex of `bytes` (the shape `tappay` reads a charge in).
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The JSON a `wallet-harness` run answered for one op (`{"ok":true,"op":"<op>","result":{…}}`), or why it did not.
fn harness_op(lines: &[String], op: &str) -> Result<serde_json::Value, String> {
    let needle = format!("\"op\":\"{op}\"");
    let line = lines.iter().find(|l| l.contains(&needle)).ok_or_else(|| format!("the wallet never answered `{op}`: {lines:?}"))?;
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("`{op}` answered no JSON: {e}: {line}"))?;
    if v["ok"] != serde_json::json!(true) {
        return Err(format!("`{op}` failed: {line}"));
    }
    Ok(v["result"].clone())
}

/// The shipped wallet's OWN seed words as a `RealWallet` on another node: the flow reported the 24 words the create screen
/// showed, and this writes them to a fresh datadir's `seed.txt` — the file `RealWallet::reopened` reopens from, the exact
/// restore path the app uses. Nothing of the UI wallet's store is reachable from the new dir: what this wallet reads, it
/// reads from the node it is pointed at. Test-only (the harness tree is `#[cfg(test)]`).
fn ui_wallet_on_node(tag: &str, phrase: &str, address: &str, node_url: &str) -> crate::harness::real_node_journey::wallet::RealWallet {
    let dir = std::env::temp_dir().join(format!("usdmw_ui_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("ui wallet dir");
    std::fs::write(dir.join("seed.txt"), phrase).expect("seed.txt");
    crate::harness::real_node_journey::wallet::RealWallet::reopened(dir, node_url, address.to_string())
}

/// ⭐ R7 F9 — STAKE USDm FROM THE SHIPPED EARN SCREEN, THE YIELD IN DOLLARS, THE UNSTAKE PATH, THE PEER READS THE STAKE.
///
/// The simulator funds the shipped wallet through node 0's faucet; the flow stakes from the Earn screen (the confirmation
/// names the dollars staked), waits until "Your stake" shows the amount once a block applies it, reads the holder yield IN
/// DOLLARS a year beside the live APR, then unstakes through its own confirmation. The flow reports the 24 words the create
/// screen showed and, once "Your stake" shows the amount, that it is staked; the simulator then reopens the SAME wallet by
/// its words against the PEER node (node 1) and reads the stake there — a stake only the UI's own node knew would read
/// `is_staking:false` on the peer. ADOPTABLE: every figure the user acts on is in dollars; nothing is lost by surprise
/// (Unstake names the principal it returns).
#[test]
fn sim_ui_stake_usdm_from_the_shipped_wallet_shows_the_yield_in_dollars_and_the_peer_reads_the_stake() {
    // A stake needs a seated custodian (MEASURED 2026-11-01, brb26/h8-pins.log: `"outcome":"NO_CUSTODIANS","published":false`
    // on a plain two-node mesh), so this mesh is raised the way F4/F6 raise theirs: custody seated, node 0's mined SAT bonded.
    let mut sim = NetSim::testnet(2, Physics::from_env(), 0xF9_2026_1101).with_band_double().boot_from_disk();
    one_chain_with_custody(&mut sim);
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    let url0 = sim.serve_rpc(0);
    let url1 = sim.serve_rpc(1);
    // PRECONDITION, named: the staking terms the Earn screen reads (`/get_stake_tree`) must name a stake epoch — the epoch of
    // the selected tip's header, 0 on a chain's first day (MEASURED 2026-11-01, brb26/h4-pins.log: the route answered 0 for
    // "no tip" and for epoch 0 alike, and the wallet refused every stake; the route now says `null` for no tip only).
    let mut terms = String::new();
    for _ in 0..120 {
        terms = sim.rpc(0, "GET", "/get_stake_tree", "").1;
        if serde_json::from_str::<serde_json::Value>(&terms).ok().and_then(|j| j["stake_epoch"].as_u64()).is_some() {
            break;
        }
        sim.run(500, 10_000);
    }
    eprintln!("[f9] node 0's staking terms: {terms}");
    assert!(
        serde_json::from_str::<serde_json::Value>(&terms).ok().and_then(|j| j["stake_epoch"].as_u64()).is_some(),
        "PRECONDITION: node 0 names no stake epoch (no selected tip): {terms}"
    );
    let amount = 5u64;
    let args = serde_json::json!({ "amount": amount, "wait_ms": 900_000 });
    let mut ui = UiProc::start("live_stake", &url0, &args).unwrap_or_else(|e| panic!("⛔ R7 F9: {e}"));
    let (mut words, mut funded, mut peer_read, mut verdict) = (None::<(String, String)>, false, None::<serde_json::Value>, None::<serde_json::Value>);
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < 2_400 {
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let (Some(addr), Some(phrase)) = (v.get("address").and_then(|a| a.as_str()), v.get("phrase").and_then(|p| p.as_str())) {
                        let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
                        assert_eq!(code, 200, "the faucet funds the shipped wallet: {body}");
                        funded = true;
                        words = Some((addr.to_string(), phrase.to_string()));
                    }
                    if v.get("staked").and_then(|s| s.as_bool()) == Some(true) && peer_read.is_none() {
                        // THE PEER'S READ, while the stake stands: the same words, pointed at node 1.
                        let (addr, phrase) = words.clone().expect("the flow reported its words before it staked");
                        let peer = ui_wallet_on_node("f9", &phrase, &addr, &url1);
                        let mut last = String::new();
                        for _ in 0..60 {
                            match run_meshing(&mut sim, &peer, &["refresh", "mystake"]).and_then(|l| harness_op(&l, "mystake")) {
                                Ok(r) if r["is_staking"].as_bool() == Some(true) => {
                                    peer_read = Some(r);
                                    break;
                                }
                                Ok(r) => last = r.to_string(),
                                Err(e) => last = e,
                            }
                            sim.run(500, 10_000);
                        }
                        assert!(peer_read.is_some(), "⛔ R7 F9: the PEER node does not read the stake the shipped wallet made (last: {last})");
                    }
                }
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(500, 10_000);
    }
    let verdict = verdict.unwrap_or_else(|| panic!("⛔ R7 F9: the shipped stake flow did not finish (funded {funded})"));
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F9: the shipped stake flow failed: {verdict}");
    let peer = peer_read.unwrap_or_else(|| panic!("⛔ R7 F9: the flow never reported the stake as shown, so the peer was never read: {verdict}"));
    assert!(
        peer["usdm"].as_f64().is_some_and(|u| u >= amount as f64),
        "⛔ R7 F9: the peer reads a different stake than the {amount} USDm the shipped wallet staked: {peer}"
    );
    let yield_usd = verdict["yield_usd"].as_str().or_else(|| verdict["result"]["yield_usd"].as_str()).unwrap_or("");
    assert!(yield_usd.starts_with('$'), "⛔ R7 F9: the Earn screen did not show the holder yield in dollars: {verdict}");
    // §17.6 (lane funds-brb33): never a button that fails after the press — Unstake is enabled only once the core's own dry run
    // says the stake can be spent, so the shipped flow's re-press loop must not have been needed. RED before (i10-f9.log): the
    // first press was refused "its member leg is not ready" and the flow pressed again until the chain folded the stake.
    let presses = verdict["presses"].as_u64().or_else(|| verdict["result"]["presses"].as_u64());
    assert_eq!(presses, Some(1), "⛔ R7 F9: the unstake needed {presses:?} presses — the Earn screen offered Unstake before the stake could be spent: {verdict}");
}

/// ⭐ R7 F12 — A TAP-TO-PAY CHARGE FROM THE SHIPPED RECEIVE SCREEN IS PAID AND SETTLES ON THE PEER.
///
/// The merchant is the shipped wallet: its Receive screen names the 0.5 % merchant fee before any charge, Charge mints the
/// ML-DSA-signed charge and shows the terminal with the signed amount, and the page reports the charge it is advertising.
/// The payer is a second real wallet (`wallet-harness`) the simulator funds; it pays the charge through `tappay` — the one
/// path that moves a tap's money (`wallet_pos_pay`: verify the signed charge fail-closed, then the WHIR send). The merchant's
/// terminal reads "✓ Paid" from the chain, and the simulator reopens the MERCHANT by its words against the PEER node and
/// reads the payment in its balance there. The BLE radio is not simulated: the charge crosses here as the bytes the radio
/// would carry, and the payment is the same chain object either way.
#[test]
fn sim_ui_a_tap_to_pay_charge_from_the_shipped_wallet_is_paid_and_settles_on_the_peer() {
    use crate::harness::real_node_journey::wallet::RealWallet;
    let mut sim = NetSim::testnet(2, Physics::from_env(), 0xF12_2026_1101).with_band_double().boot_from_disk();
    one_chain_with_custody(&mut sim);
    let url0 = sim.serve_rpc(0);
    let url1 = sim.serve_rpc(1);
    let amount = 2.5f64;
    // The payer: a real wallet on node 0, funded by the faucet, spendable before the merchant charges.
    let payer = RealWallet::create("f12", "payer", &url0).unwrap_or_else(|e| panic!("⛔ R7 F12: {e}"));
    let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, payer.address));
    assert_eq!(code, 200, "the faucet funds the payer: {body}");
    let mut spendable = 0u64;
    for _ in 0..240 {
        if let Ok(r) = run_meshing(&mut sim, &payer, &["refresh", "balance"]).and_then(|l| harness_op(&l, "balance")) {
            spendable = r["atomic"].as_u64().unwrap_or(0);
            if spendable >= 2_500_000_000 {
                break;
            }
        }
        sim.run(500, 10_000);
    }
    assert!(spendable >= 2_500_000_000, "PRECONDITION: the payer's funding never became spendable ({spendable} atomic)");
    let args = serde_json::json!({ "amount": amount, "wait_ms": 900_000 });
    let mut ui = UiProc::start("live_pos_charge", &url0, &args).unwrap_or_else(|e| panic!("⛔ R7 F12: {e}"));
    let (mut merchant, mut paid, mut verdict) = (None::<(String, String)>, None::<serde_json::Value>, None::<serde_json::Value>);
    let wall = std::time::Instant::now();
    while wall.elapsed().as_secs() < 2_400 {
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let (Some(addr), Some(phrase), Some(charge)) = (v.get("address").and_then(|a| a.as_str()), v.get("phrase").and_then(|p| p.as_str()), v.get("charge")) {
                        merchant = Some((addr.to_string(), phrase.to_string()));
                        assert_eq!(charge["address"].as_str(), Some(addr), "the charge pays the MERCHANT — the address its own wallet sealed");
                        assert_eq!(charge["amount_usdm"].as_f64(), Some(amount), "the charge signed the amount the screen took: {charge}");
                        // THE PAYMENT: the payer pays the charge bytes the radio would have carried.
                        let hex = hex_of(&serde_json::to_vec(charge).expect("charge bytes"));
                        let (ok, _secs, reply) = pay_meshing(&mut sim, &payer, &format!("tappay {hex}"), "tappay", 420);
                        assert!(ok, "⛔ R7 F12: the payer could not pay the shipped wallet's charge: {reply}");
                        let r: serde_json::Value = serde_json::from_str(&reply).unwrap_or_default();
                        assert_eq!(r["result"]["paid"], serde_json::json!(true), "⛔ R7 F12: tappay did not pay: {reply}");
                        paid = Some(r["result"].clone());
                    }
                }
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(500, 10_000);
    }
    let verdict = verdict.unwrap_or_else(|| panic!("⛔ R7 F12: the shipped charge flow did not finish (paid {paid:?})"));
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F12: the shipped charge flow failed: {verdict}");
    let paid = paid.unwrap_or_else(|| panic!("⛔ R7 F12: the flow never reported a charge, so nothing was paid: {verdict}"));
    assert_eq!(paid["amount_usdm"].as_f64(), Some(amount), "the payer paid exactly the signed amount: {paid}");
    // THE PEER HOLDS IT: the merchant, reopened by its words against node 1, reads the payment in its balance.
    let (addr, phrase) = merchant.expect("the merchant reported its words");
    let peer = ui_wallet_on_node("f12", &phrase, &addr, &url1);
    let want = (amount * 1e8) as u64;
    let mut got = 0u64;
    for _ in 0..240 {
        if let Ok(r) = run_meshing(&mut sim, &peer, &["refresh", "balance"]).and_then(|l| harness_op(&l, "balance")) {
            got = r["atomic"].as_u64().unwrap_or(0);
            if got >= want {
                break;
            }
        }
        sim.run(500, 10_000);
    }
    assert!(got >= want, "⛔ R7 F12: the PEER node serves the merchant {got} atomic, not the {want} the tap paid");
}

/// A 32-byte hex field of a wallet answer, or `None`.
fn hex32_of(s: Option<&str>) -> Option<[u8; 32]> {
    let s = s?.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// ⭐⭐ R7 F13 — A DSOL CALL FROM THE SHIPPED WALLET PAYS THE PUBLISHER ON THE PEER (§BR-12).
///
/// The PUBLISHER is a real wallet (`wallet-harness`) on node 1, funded by the faucet: it deploys the fixture contract with a
/// $0.50 publisher fee through the one deploy builder (`dsoldeploy`), and BOTH nodes' contract-state roots move to the deploy's
/// leaf (the object crossed the wire to node 0). The CALLER is the shipped wallet on node 0: the launchpad app's `dsolCall`
/// opens the one confirmation naming the publisher fee in dollars; the core verifies the app's manifest + storage against the
/// chain's root, proves the call as its own per-contract pseudonym and pays the fee into the publisher's public opening. The
/// simulator then asserts on node 1, fed only by the mesh: the contract-state root moved to the post-call leaf, and the
/// PUBLISHER's wallet, reading its own node, holds the fee in its balance (its ordinary scan found the public-seed note). The
/// dollars the dialog showed are the dollars the core paid.
/// TWO-PARTY-REVIEWED: the deploy is asserted on node 0 from node 1's object; the call on node 1 from node 0's object.
#[test]
fn sim_ui_a_dsol_call_from_the_shipped_wallet_pays_the_publisher_on_the_peer() {
    use crate::harness::real_node_journey::wallet::RealWallet;
    let mut sim = NetSim::testnet(2, Physics::from_env(), 0xF13_2026_1101).with_band_double().boot_from_disk();
    one_chain_with_custody(&mut sim);
    let url0 = sim.serve_rpc(0);
    let url1 = sim.serve_rpc(1);
    let fee_usdm = 0.5f64;
    let fee_atomic = 50_000_000u64;
    let empty_root_hex = hex_of(&crate::spend_frontier::leaf_to_cm_bytes(crate::contract_state::empty_root()));
    // THE PUBLISHER on node 1, funded by the faucet.
    let publisher = RealWallet::create("f13", "publisher", &url1).unwrap_or_else(|e| panic!("⛔ R7 F13: {e}"));
    let (code, body) = sim.rpc(1, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{}"}}"#, publisher.address));
    assert_eq!(code, 200, "the faucet funds the publisher: {body}");
    let price = crate::dsol_deploy_tx::dsol_deploy_fee_atomic();
    let mut spendable = 0u64;
    for _ in 0..240 {
        if let Ok(r) = run_meshing(&mut sim, &publisher, &["refresh", "balance"]).and_then(|l| harness_op(&l, "balance")) {
            spendable = r["atomic"].as_u64().unwrap_or(0);
            if spendable >= 2_500_000_000 {
                break;
            }
        }
        sim.run(500, 10_000);
    }
    assert!(spendable >= 2_500_000_000, "PRECONDITION: the publisher's funding never became spendable ({spendable} atomic)");
    let code_hex = hex_of(&crate::dsol_call_tx::fixtures::program());
    let deploy_cmd = format!("dsoldeploy {code_hex} {} f13-fixture {fee_usdm}", crate::dsol_call_tx::fixtures::HEIGHT_CLASS);
    let dep = run_meshing(&mut sim, &publisher, &["refresh", &deploy_cmd])
        .and_then(|l| harness_op(&l, "dsoldeploy"))
        .unwrap_or_else(|e| panic!("⛔ R7 F13: the publisher could not deploy: {e}"));
    let cid = hex32_of(dep["cid"].as_str()).expect("the deploy names its cid");
    let leaf = crate::spend_frontier::cm_bytes_to_root(&hex32_of(dep["leaf_hex"].as_str()).expect("the deploy names its leaf")).expect("canonical");
    assert_eq!(dep["manifest"]["publisher_fee_atomic"].as_u64(), Some(fee_atomic), "the deploy carries the fee the publisher set: {dep}");
    let mut tree = crate::contract_state::ContractStateTree::new();
    tree.insert(cid, leaf);
    let want_root = hex_of(&crate::spend_frontier::leaf_to_cm_bytes(tree.root()));
    assert_ne!(want_root, empty_root_hex);
    // BOTH nodes fold the deploy (node 0 from the wire).
    let root_of = |sim: &NetSim, i: usize| -> String {
        serde_json::from_str::<serde_json::Value>(&sim.rpc(i, "GET", "/contract_state_root", "").1)
            .ok()
            .and_then(|v| v["root"].as_str().map(String::from))
            .unwrap_or_default()
    };
    let mut roots = (String::new(), String::new());
    for _ in 0..600 {
        roots = (root_of(&sim, 0), root_of(&sim, 1));
        if roots.0 == want_root && roots.1 == want_root {
            break;
        }
        sim.run(500, 10_000);
    }
    assert_eq!(roots, (want_root.clone(), want_root.clone()), "⛔ R7 F13: the deploy did not reach both nodes' contract-state roots (want {want_root})");
    // THE CALLER: the shipped wallet on node 0, handed the APP's call (the publisher's manifest, view key, code and path).
    let path = tree.path(&cid);
    let call = serde_json::json!({
        "cid": hex_of(&cid),
        "manifest": dep["manifest"].clone(),
        "view_ek": dep["view_ek_hex"].clone(),
        "code": code_hex,
        "entrypoint": "main",
        "argv": "",
        "height_class": crate::dsol_call_tx::fixtures::HEIGHT_CLASS,
        "storage": [],
        "state_path": { "mask": hex_of(&path.mask), "sibs": path.sibs.iter().map(|s| hex_of(s)).collect::<Vec<_>>() },
    });
    let args = serde_json::json!({ "call": call, "wait_ms": 900_000, "call_wait_ms": 900_000 });
    let mut ui = UiProc::start("live_dsol_call", &url0, &args).unwrap_or_else(|e| panic!("⛔ R7 F13: {e}"));
    let (mut funded, mut core, mut verdict) = (false, None::<serde_json::Value>, None::<serde_json::Value>);
    let wall = std::time::Instant::now();
    // THE CHAIN RUNS AT ITS REAL PACE while the shipped wallet proves in real time: 500 ms of simulated chain per 500 ms of
    // wall clock. MEASURED (h6-f13-journey.log): run flat out, the simulator folded ~880 records (hundreds of 64-block
    // epochs) during one WHIR proof of ~60 s, so an honest call was always epochs stale at its block — a simulator artefact
    // no real chain shows (its blocks take 500 ms of wall time each). Pacing here models the chain, it does not loosen it.
    while wall.elapsed().as_secs() < 2_400 {
        let tick = std::time::Instant::now();
        while let Ok(v) = ui.rx.try_recv() {
            match v.get("t").and_then(|x| x.as_str()) {
                Some("emit") => {
                    if let Some(addr) = v.get("address").and_then(|a| a.as_str()) {
                        let (code, body) = sim.rpc(0, "POST", "/faucet/drip", &format!(r#"{{"amount":2500000000,"to":"{addr}"}}"#));
                        assert_eq!(code, 200, "the faucet funds the shipped wallet: {body}");
                        funded = true;
                    }
                }
                Some("core") if v.get("cmd").and_then(|c| c.as_str()) == Some("dapp_provider_dsol_call") => core = Some(v["value"].clone()),
                _ if v.get("ok").is_some() => verdict = Some(v),
                _ => {}
            }
        }
        if ui.exited() && verdict.is_some() {
            break;
        }
        sim.run(500, 10_000);
        if let Some(rest) = std::time::Duration::from_millis(500).checked_sub(tick.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    let verdict = verdict.unwrap_or_else(|| panic!("⛔ R7 F13: the shipped call flow did not finish (funded {funded})"));
    assert_eq!(verdict["ok"], serde_json::json!(true), "⛔ R7 F13: the shipped call flow failed: {verdict}");
    let core = core.unwrap_or_else(|| panic!("⛔ R7 F13: the core never answered the call: {verdict}"));
    assert_eq!(core["status"].as_str(), Some("OK"), "⛔ R7 F13: the core refused the call: {core}");
    assert_eq!(core["publisher_fee_atomic"].as_u64(), Some(fee_atomic), "the core paid exactly the deployed fee: {core}");
    let shown = verdict["shown_fee_usd"].as_f64().or_else(|| verdict["result"]["shown_fee_usd"].as_f64()).unwrap_or(f64::NAN);
    assert!((shown - fee_usdm).abs() < 1e-9, "⛔ R7 F13: the dialog showed ${shown}, the core paid ${fee_usdm}: {verdict}");
    // THE PEER (node 1) folds the call: its root is the post-call leaf's.
    let storage_post = crate::spend_frontier::cm_bytes_to_root(&hex32_of(core["storage_post_hex"].as_str()).expect("the core names the post storage")).expect("canonical");
    let manifest = crate::dsol_deploy_tx::ContractManifest {
        code_id: hex32_of(dep["manifest"]["code_id"].as_str()).expect("code_id"),
        publisher_fee_le: fee_atomic.to_le_bytes(),
        publisher_spk: hex32_of(dep["manifest"]["publisher_spk"].as_str()).expect("publisher_spk"),
        deployer_id: hex32_of(dep["manifest"]["deployer_id"].as_str()).expect("deployer_id"),
        kc_commit: hex32_of(dep["manifest"]["kc_commit"].as_str()).expect("kc_commit"),
        height_class: u8::try_from(dep["manifest"]["height_class"].as_u64().expect("height_class")).expect("a class"),
    };
    let mut after = tree.clone();
    after.insert(cid, manifest.leaf(storage_post));
    let want_after = hex_of(&crate::spend_frontier::leaf_to_cm_bytes(after.root()));
    assert_ne!(want_after, want_root, "the call moved the storage (it SSTOREs)");
    let mut peer_root = String::new();
    for _ in 0..600 {
        peer_root = root_of(&sim, 1);
        if peer_root == want_after {
            break;
        }
        sim.run(500, 10_000);
    }
    assert_eq!(peer_root, want_after, "⛔ R7 F13: the PEER node's contract-state root did not move to the post-call leaf");
    // THE PUBLISHER IS PAID: its own node's scan finds the public-seed fee note; its balance grows by the fee.
    let before_fee = 2_500_000_000u64 - price - usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC;
    let mut got = 0u64;
    for _ in 0..600 {
        if let Ok(r) = run_meshing(&mut sim, &publisher, &["refresh", "balance"]).and_then(|l| harness_op(&l, "balance")) {
            got = r["atomic"].as_u64().unwrap_or(0);
            if got >= before_fee + fee_atomic {
                break;
            }
        }
        sim.run(500, 10_000);
    }
    assert!(
        got >= before_fee + fee_atomic,
        "⛔ R7 F13: the publisher holds {got} atomic, not the {} the deploy left plus the ${fee_usdm} fee",
        before_fee + fee_atomic
    );
}

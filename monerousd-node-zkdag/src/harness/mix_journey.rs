// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-6 B6-c — THE ENTRY MIX ON THE SIMULATED MESH: the epoch's designated custodian coordinates a round over the real
//! RPC routes (`/mix_rounds`, `/mix_send`, `/mix_answer`), the real round view relayed node to node, the real registration
//! transport (a bulk ask aimed at the coordinator's address), and the simulated Bitcoin; four users split across BOTH nodes
//! each mix one ladder unit, and the round's transaction confirms paying every output exactly one unit.
//! TWO-PARTY-REVIEWED: users sit on both nodes; whichever node coordinates, half the registrations cross the simulated wire,
//! and every user reads the round only from its own node.

use crate::entry_mix as em;
use crate::harness::netsim::{NetSim, Physics};

pub(crate) struct User {
    pub(crate) node: usize,
    pub(crate) secret: [u8; 32],
    pub(crate) coin: ([u8; 32], u32, u64),
    pub(crate) cred: em::Credential,
    pub(crate) out_spk: Vec<u8>,
    pub(crate) out_addr: String,
    pub(crate) change_spk: Vec<u8>,
    pub(crate) stage: u8,
    pub(crate) hash: String,
    pub(crate) terms: Option<em::RoundTerms>,
    /// The epoch of the round `terms` names (a round that passes unfilled is left for the next one, as a wallet does).
    pub(crate) epoch: u64,
}

pub(crate) fn vault(tag: &str, i: usize) -> ([u8; 32], Vec<u8>, String) {
    let seed: [u8; 32] = *blake3::hash(format!("mix-journey/{tag}/{i}").as_bytes()).as_bytes();
    let (x, dq) = crate::btc_tx::vault_single_key_output(&seed).expect("a hash is a key"); // CLASSICAL-CRYPTO-EXEMPT: a test vault on Bitcoin's own curve (bridge endpoint)
    (dq, crate::btc_tx::p2tr_script_pubkey(&x), crate::btc_tx::reserve_address("bcrt", &x))
}

pub(crate) fn clock(sim: &NetSim) -> u64 {
    sim.rt(0).now_unix_ms()
}

fn views(sim: &NetSim, node: usize) -> (u64, Vec<em::RoundView>) {
    let (code, body) = sim.rpc(node, "POST", "/mix_rounds", "{}");
    assert_eq!(code, 200, "/mix_rounds answers: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let now = v["now_ms"].as_u64().expect("clock");
    let views = v["views"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(|h| crate::btc_tx::unhex(h)).filter_map(|b| em::RoundView::decode(&b)).collect()).unwrap_or_default();
    (now, views)
}

fn send(sim: &NetSim, node: usize, req: &[u8]) -> Result<String, String> {
    let (_, body) = sim.rpc(node, "POST", "/mix_send", &format!(r#"{{"request_hex":"{}"}}"#, crate::btc_tx::hex(req)));
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    v["request"].as_str().map(str::to_string).ok_or_else(|| v["reason"].as_str().unwrap_or("not sent").to_string())
}

fn answer(sim: &NetSim, node: usize, h: &str) -> Option<Result<(), String>> {
    let (_, body) = sim.rpc(node, "POST", "/mix_answer", &format!(r#"{{"request":"{h}"}}"#));
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    match v["accepted"].as_bool()? {
        true => Some(Ok(())),
        false => Some(Err(v["reason"].as_str().unwrap_or("refused").to_string())),
    }
}

/// One step of a user's round client (the wallet's `mix_client` in miniature: the same `entry_mix` calls, over the node).
pub(crate) fn step(sim: &NetSim, u: &mut User, denom: u64) {
    let before = u.stage;
    step_inner(sim, u, denom);
    if u.stage != before {
        let now = clock(sim);
        // a test user's stage change, with the epoch it acts in: how a round's fill is read (harness only)
        eprintln!("[mix-user] node {} stage {before} → {} at epoch {} (t {} s into it)", u.node, u.stage, now / em::MIX_EPOCH_MS, (now % em::MIX_EPOCH_MS) / 1000);
    }
}

fn step_inner(sim: &NetSim, u: &mut User, denom: u64) {
    let (now, vs) = views(sim, u.node);
    let (epoch, t) = (now / em::MIX_EPOCH_MS, now % em::MIX_EPOCH_MS);
    // a round that did not fill (still registering or awaiting its record when its epoch passed) is left: the user joins the
    // next round with a fresh credential, exactly as the shipped wallet does ("That round did not fill; joining the next
    // round") — a user parked on a dead round forever kept the next round under its input floor
    if (1..=2).contains(&u.stage) && epoch > u.epoch {
        u.stage = 0;
        u.terms = None;
        u.cred = em::Credential::fresh().expect("entropy");
    }
    match u.stage {
        0 => {
            if t + 15_000 > em::MIX_INPUTS_END_MS {
                return;
            }
            let Some(v0) = vs.iter().find(|v| v.epoch == epoch) else { return };
            let terms = em::RoundTerms::for_epoch(v0.terms.coordinator_pk.clone(), denom, v0.terms.fee_rate_sat_vb, epoch).expect("terms");
            let reg = em::sign_input_registration(&terms, &u.coin.0, u.coin.1, std::slice::from_ref(&u.cred), &u.change_spk, &u.secret).expect("signed");
            if let Ok(h) = send(sim, u.node, &em::MixRequest::Input(reg).encode(&terms.round_id)) {
                u.hash = h;
                u.terms = Some(terms);
                u.epoch = epoch;
                u.stage = 1;
            }
        }
        1 => match answer(sim, u.node, &u.hash) {
            Some(Ok(())) => u.stage = 2,
            Some(Err(why)) => panic!("⛔ the coordinator refused an honest input: {why}"),
            None => {}
        },
        2 => {
            let terms = u.terms.clone().expect("terms");
            let Some(v) = vs.iter().find(|v| v.terms.round_id == terms.round_id && v.phase == em::Phase::Outputs) else { return };
            let (leaves, root, sig) = v.record.clone().expect("an outputs view carries its record");
            assert!(em::check_record(&terms, &leaves, &root, &sig, &u.cred).is_some(), "the user's own node relays the signed record holding its credential");
            let o = em::prove_output(&terms, &leaves, &u.cred, &u.out_spk).expect("the burn proves");
            if let Ok(h) = send(sim, u.node, &em::MixRequest::Output(o).encode(&terms.round_id)) {
                u.hash = h;
                u.stage = 3;
            }
        }
        3 => match answer(sim, u.node, &u.hash) {
            Some(Ok(())) => u.stage = 4,
            Some(Err(why)) => panic!("⛔ the coordinator refused an honest output: {why}"),
            None => {}
        },
        4 => {
            let terms = u.terms.clone().expect("terms");
            let Some(v) = vs.iter().find(|v| v.terms.round_id == terms.round_id && v.phase == em::Phase::Signing) else { return };
            let tx = v.tx.clone().expect("a signing view carries its transaction");
            let change = terms.change_for(u.coin.2, 1).expect("covers").map(|c| (u.change_spk.clone(), c));
            let idx = em::may_sign(&terms, &tx, (&u.coin.0, u.coin.1, u.coin.2), std::slice::from_ref(&u.out_spk), change.as_ref().map(|(s, c)| (s.as_slice(), *c)))
                .expect("⛔ the round's transaction does not pay this user's output and change");
            let sig = em::sign_round_input(&tx, idx, &u.secret).expect("signed");
            if let Ok(h) = send(sim, u.node, &em::MixRequest::Sign { txid: u.coin.0, vout: u.coin.1, sig }.encode(&terms.round_id)) {
                u.hash = h;
                u.stage = 5;
            }
        }
        _ => {}
    }
}

/// ⭐⭐⭐ R6 §BR-6 / R8 — four users on two nodes mix through the mesh's own custodian and the round confirms on Bitcoin.
#[test]
fn sim_br6_four_users_on_two_nodes_mix_a_ladder_unit_each_and_the_round_confirms_on_bitcoin() {
    let _serial = crate::btc_sim::serial().lock().unwrap_or_else(|e| e.into_inner());
    let seed = 0xB6C0_2026_1029u64;
    let mut sim = NetSim::testnet(2, Physics::from_env(), seed).with_band_double().with_sim_bitcoin(seed, 60_000).boot_from_disk();
    let mut t = 0u64;
    while !(sim.one_chain_between(0, 1) && (0..2).all(|i| sim.rt(i).node().validators().bonded_ids().len() == 2)) && t < 600_000 {
        sim.run(1_000, 10_000);
        t += 1_000;
    }
    assert!(sim.one_chain_between(0, 1), "PRECONDITION: one chain");
    assert_eq!(sim.rt(0).node().validators().bonded_ids().len(), 2, "PRECONDITION: both daemons hold their seats");
    // the coordinator is a CUSTODY-seated id (the rotation and the act read one set): node 0 bonds its mined SAT, as an operator does
    assert!(sim.seat_sat_custody(0, 900_000), "PRECONDITION: node 0 bonds the SAT it mined as custody weight on both nodes");
    let denom = 100_000u64;
    let mut users: Vec<User> = (0..4)
        .map(|i| {
            let (secret, _, addr) = vault("coin", i);
            let txid = sim.btc().fund(&addr, denom + 40_000).expect("funded");
            sim.btc().mine(1);
            let (_, out_spk, out_addr) = vault("out", i);
            let (_, change_spk, _) = vault("change", i);
            User { node: i % 2, secret, coin: (txid, 0, denom + 40_000), cred: em::Credential::fresh().expect("entropy"), out_spk, out_addr, change_spk, stage: 0, hash: String::new(), terms: None, epoch: 0 }
        })
        .collect();
    let start = clock(&sim);
    while users.iter().any(|u| u.stage < 5) && clock(&sim) - start < 3 * em::MIX_EPOCH_MS {
        sim.run(2_000, 10_000);
        for u in users.iter_mut() {
            step(&sim, u, denom);
        }
    }
    assert!(users.iter().all(|u| u.stage == 5), "⛔ every user signed within three epochs: stages {:?}", users.iter().map(|u| u.stage).collect::<Vec<_>>());
    // the coordinator broadcasts at the signing deadline; Bitcoin mines a block a minute
    let deadline = clock(&sim) + 3 * 60_000 + em::MIX_EPOCH_MS;
    while clock(&sim) < deadline && !users.iter().all(|u| sim.btc().received_sats(&u.out_addr) == denom) {
        sim.run(5_000, 10_000);
    }
    for u in &users {
        assert_eq!(sim.btc().received_sats(&u.out_addr), denom, "⛔ the round paid this output exactly one ladder unit on Bitcoin");
    }
    eprintln!("[measure] br6 mesh round: 4 users on 2 nodes, confirmed {} sim-ms after the first registration", clock(&sim) - start);
}

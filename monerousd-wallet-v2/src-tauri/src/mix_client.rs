// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-6 B6-b — ADD MONEY WITH BITCOIN, PRIVATELY: the wallet's entry-mix round client
//! (docs/BR-6-ENTRY-MIX-SPEC-20261029.md; the node's half is `usdmd_node::entry_mix`).
//!
//! The user sends Bitcoin from anywhere to a fresh address of the wallet's own vault (BIP 86, derived from the 24 words).
//! Once it confirms, the wallet mixes it without being asked again: each round takes the coin's leading decimal digit — up
//! to nine ladder units of one size, the round's only size — into a WabiSabi-shaped CoinJoin whose every output is a fresh
//! co-signed deposit address (§BR-2) of this wallet, and the rest comes back to a fresh vault address as change for the next
//! round. Each mixed output then mints through the ordinary deposit lane. Nothing is trusted: the wallet signs its coin
//! only when the round's transaction pays every one of its outputs and its change exactly (`entry_mix::may_sign`), so a
//! coordinator that cheats gets no signature and nothing moves. What stays under the smallest ladder unit stays in the
//! vault, shown in dollars.
//!
//! Privacy on the wire: every registration goes point to point to the coordinator on a fresh Tor circuit (the node's
//! `mix_send`); each output registration leaves at its own random instant inside the output phase, so the coordinator's
//! arrival order says nothing about which input it belongs to. The credential's one-time keys live in this file only for
//! the round (a crash mid-round leaves the coin unsigned: it stays the user's, and the next round re-mixes it).

use super::*;
use serde::{Deserialize, Serialize};
use usdmd_node::entry_mix as em;
use usdmd_node::spend_frontier::{digest_from_lane_bytes, digest_to_lane_bytes, DIGEST_LANE_BYTES};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct MixCred {
    /// The one-time credential owner, `ask ‖ nk ‖ seed` lane bytes (hex) — on this device only, for this round only.
    owner_hex: String,
    swap_id: String,
    deposit_address: String,
    out_spk_hex: String,
    /// The node-clock instant this credential's output registration leaves (random inside the output phase).
    send_at_ms: u64,
    out_req_hex: String,
    out_hash_hex: String,
    out_ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct MixRound {
    epoch: u64,
    denom: u64,
    fee_rate: u64,
    coordinator_pk_hex: String,
    creds: Vec<MixCred>,
    change_index: Option<u32>,
    change_value: Option<u64>,
    change_vout: Option<u32>,
    in_req_hex: String,
    in_hash_hex: String,
    in_ok: bool,
    in_sent_ms: u64,
    signed: bool,
    txid_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct MixPlan {
    plan_id: String,
    key_id_hex: String,
    created_ms: u64,
    /// The vault index of the address the user funds.
    receive_index: u32,
    /// The coin being mixed now: (txid display hex, vout, sats, its vault index).
    coin: Option<(String, u32, u64, u32)>,
    /// awaiting_funds | mixing | done
    status: String,
    /// The plain-language state the screen shows.
    note: String,
    current: Option<MixRound>,
    rounds_done: u32,
    /// The deposit swaps the mixed outputs fund (each mints through the ordinary deposit lane).
    swaps: Vec<String>,
    /// What stayed in the vault (under the smallest ladder unit), in sats.
    left_in_vault: u64,
    /// §BR-8 B8-b: a remixer's plan (started by the switch from a free vault coin, not by the user).
    #[serde(default)]
    remix: bool,
    /// §BR-8 B8-b: the remix plan's minted deposits were cashed back out to the vault.
    #[serde(default)]
    cashed: bool,
    /// A COIN SWAP's target `(asset, payout address)`: once every mixed deposit has minted, the plan's USDm is cashed out to it
    /// (`coin_swap_mix_tick`). `None` for a plain private deposit.
    #[serde(default)]
    then_pay: Option<(String, String)>,
    /// A BUY SAT's maximum-price bucket (spec §18.3 with Auto-OPSEC): once every mixed deposit has minted, the plan's USDm is
    /// one sealed SAT order (`sat_buy_mix_ready` → `defi_buy::sat_buy_mix_tick`). `None` for a plain private deposit.
    #[serde(default)]
    then_buy: Option<usize>,
    /// The Buy SAT's order was placed (or failed and said so) — claimed before it runs, so no tick places it twice.
    #[serde(default)]
    bought: bool,
}

fn mix_path_scoped() -> Option<PathBuf> {
    let kid = current_key_id_hex()?;
    let cid = current_chain_id();
    let cid = if cid.is_empty() { "nochain".to_string() } else { cid };
    Some(node_data_dir().join(format!("v2wallet-mix-{}-{}.json", &kid[..kid.len().min(16)], &cid[..cid.len().min(16)])))
}
fn read_mixes() -> Vec<MixPlan> {
    let Some(path) = mix_path_scoped() else { return Vec::new() };
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Vec<MixPlan>>(&b).ok()).unwrap_or_default()
}
fn write_mixes(list: &[MixPlan]) {
    if let Some(path) = mix_path_scoped() {
        if let Ok(bytes) = serde_json::to_vec(list) {
            let _ = std::fs::write(path, bytes);
        }
    }
}

/// The highest vault index any mix plan drew (its receive address, its coins, its change) — `vault_next_index` reads it.
pub(crate) fn max_vault_index() -> Option<u32> {
    read_mixes()
        .iter()
        .flat_map(|p| {
            let cur = p.current.as_ref().and_then(|c| c.change_index);
            [Some(p.receive_index), p.coin.as_ref().map(|c| c.3), cur]
        })
        .flatten()
        .max()
}

fn owner_hex(c: &em::Credential) -> String {
    let mut b = Vec::with_capacity(3 * DIGEST_LANE_BYTES);
    b.extend_from_slice(&digest_to_lane_bytes(&c.owner.ask));
    b.extend_from_slice(&digest_to_lane_bytes(&c.owner.nk));
    b.extend_from_slice(&digest_to_lane_bytes(&c.owner.seed));
    hex::encode(b)
}
fn owner_of(h: &str) -> Option<em::Credential> {
    let b = hex::decode(h).ok()?;
    if b.len() != 3 * DIGEST_LANE_BYTES {
        return None;
    }
    let d = |i: usize| digest_from_lane_bytes(&b[i * DIGEST_LANE_BYTES..(i + 1) * DIGEST_LANE_BYTES]);
    Some(em::Credential { owner: usdm_decider::whir_rec_block::NoteOwner { ask: d(0)?, nk: d(1)?, seed: d(2)? } })
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build()
}

/// The node's clock and the current epoch's round views (each decoded and signature-checked here, never trusted).
fn fetch_views() -> Result<(u64, Vec<em::RoundView>), String> {
    let v: serde_json::Value = agent()
        .post(&format!("{}/mix_rounds", node_url()))
        .send_json(serde_json::json!({}))
        .map_err(|e| format!("mix rounds: {}", node_refusal(e)))?
        .into_json()
        .map_err(|e| format!("mix rounds json: {e}"))?;
    let now = v["now_ms"].as_u64().ok_or("mix rounds: no clock")?;
    let views = v["views"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(|h| hex::decode(h).ok()).filter_map(|b| em::RoundView::decode(&b)).collect())
        .unwrap_or_default();
    Ok((now, views))
}

fn send(req: &[u8]) -> Result<String, String> {
    let v: serde_json::Value = agent()
        .post(&format!("{}/mix_send", node_url()))
        .send_json(serde_json::json!({ "request_hex": hex::encode(req) }))
        .map_err(|e| format!("mix send: {}", node_refusal(e)))?
        .into_json()
        .map_err(|e| format!("mix send json: {e}"))?;
    match v["request"].as_str() {
        Some(h) => Ok(h.to_string()),
        None => Err(v["reason"].as_str().unwrap_or("the node did not send the registration").to_string()),
    }
}

fn answer(hash_hex: &str) -> Option<Result<(), String>> {
    let v: serde_json::Value = agent().post(&format!("{}/mix_answer", node_url())).send_json(serde_json::json!({ "request": hash_hex })).ok()?.into_json().ok()?;
    match v["accepted"].as_bool()? {
        true => Some(Ok(())),
        false => Some(Err(v["reason"].as_str().unwrap_or("refused").to_string())),
    }
}

/// The largest coin the node sees at `address`: (txid display, vout, sats, confirmations).
fn best_coin(address: &str) -> Option<(String, u32, u64, u64)> {
    let v: serde_json::Value = agent().post(&format!("{}/btc_deposit_coin", node_url())).send_json(serde_json::json!({ "address": address })).ok()?.into_json().ok()?;
    v["coins"].as_array()?.iter().max_by_key(|c| c["value_sats"].as_u64().unwrap_or(0)).and_then(|c| {
        Some((c["txid"].as_str()?.to_string(), u32::try_from(c["vout"].as_u64()?).ok()?, c["value_sats"].as_u64()?, c["confirmations"].as_u64().unwrap_or(0)))
    })
}

/// The coin `txid:vout` at `address`, when the node sees it, with its confirmations.
fn coin_confs(address: &str, txid: &str) -> Option<u64> {
    let v: serde_json::Value = agent().post(&format!("{}/btc_deposit_coin", node_url())).send_json(serde_json::json!({ "address": address })).ok()?.into_json().ok()?;
    v["coins"].as_array()?.iter().find(|c| c["txid"].as_str() == Some(txid)).map(|c| c["confirmations"].as_u64().unwrap_or(0))
}

fn mint_ratio_bps() -> Result<u64, String> {
    agent()
        .post(&format!("{}/get_governance", node_url()))
        .send_json(serde_json::json!({}))
        .ok()
        .and_then(|r| r.into_json::<serde_json::Value>().ok())
        .and_then(|j| j.get("mint_ratio_bps").and_then(|r| r.as_u64()))
        .filter(|b| *b > 0)
        .ok_or_else(|| "could not reach the node".to_string())
}

/// The USDm one ladder unit of `sats` mints at the chain's mark and backing ratio, less the deposit's sweep fee, with a 3 %
/// price margin (the deposit is priced again when it mints) and rounded down to a cent.
fn usdm_for_unit(sats: u64, price: u128, scale: u128, backing_bps: u64) -> f64 {
    let net = u128::from(sats.saturating_sub(SWEEP_FEE_SATS));
    let atomic = net.saturating_mul(price).saturating_mul(10_000) / scale.max(1).saturating_mul(u128::from(backing_bps.max(1)));
    let atomic = atomic * 97 / 100 / 1_000_000 * 1_000_000;
    atomic as f64 / 1e8
}

/// The leading digit a coin of `value` mixes this round: the largest ladder unit it covers and how many of it (≤ 9, so one
/// round takes one whole decimal digit), with its fee and change paid.
fn leading_digit(pk: &[u8], fee: u64, epoch: u64, value: u64) -> Option<(em::RoundTerms, usize)> {
    for d in usdmd_node::peg_pool::PAYOUT_DENOMS.iter().rev() {
        let terms = em::RoundTerms::for_epoch(pk.to_vec(), *d, fee, epoch)?;
        let mut k = usize::try_from(value / d).unwrap_or(usize::MAX).min(em::CREDS_PER_INPUT_MAX);
        while k > 0 && terms.change_for(value, k).is_err() {
            k -= 1;
        }
        if k > 0 {
            return Some((terms, k));
        }
    }
    None
}

fn expire_swaps(ids: &[String]) {
    let mut swaps = read_swaps();
    for s in swaps.iter_mut().filter(|s| ids.contains(&s.swap_id) && s.status == "awaiting_deposit") {
        s.status = "expired".into(); // never funded: the round did not happen, nothing was sent there
    }
    write_swaps(&swaps);
}

fn terms_of(r: &MixRound) -> Option<em::RoundTerms> {
    em::RoundTerms::for_epoch(hex::decode(&r.coordinator_pk_hex).ok()?, r.denom, r.fee_rate, r.epoch)
}

/// One step of a plan. Every network call is bounded; a failure leaves the plan where it was (the next poll retries).
pub(crate) fn advance_mix(plan: &mut MixPlan) {
    let before = (plan.status.clone(), plan.note.clone(), plan.rounds_done);
    advance_mix_inner(plan);
    if before != (plan.status.clone(), plan.note.clone(), plan.rounds_done) {
        // DIGITAL-CASH-PRIVACY-REVIEWED: the plan's own user-facing status line and a round COUNT, local stderr only — no
        // coin, address, amount, credential or key.
        eprintln!("[mix] {} · {} round(s) done · {}", plan.status, plan.rounds_done, plan.note);
    }
}

fn advance_mix_inner(plan: &mut MixPlan) {
    match plan.status.as_str() {
        "awaiting_funds" => {
            let Ok((_, _, addr)) = vault_keys_at(plan.receive_index) else { return };
            match best_coin(&addr) {
                Some((txid, vout, value, confs)) if confs >= 1 => {
                    plan.coin = Some((txid, vout, value, plan.receive_index));
                    plan.status = "mixing".into();
                    plan.note = "Your Bitcoin arrived. Making your deposit private · about 2 min per step".into();
                }
                Some(_) => plan.note = "Your Bitcoin is on its way — waiting for its first confirmation".into(),
                None => plan.note = "Waiting for your Bitcoin".into(),
            }
        }
        "mixing" => step_mixing(plan),
        _ => {}
    }
}

fn step_mixing(plan: &mut MixPlan) {
    let Some((coin_txid, coin_vout, coin_value, coin_index)) = plan.coin.clone() else {
        plan.status = "done".into();
        return;
    };
    let (now, views) = match fetch_views() {
        Ok(v) => v,
        Err(e) => {
            plan.note = format!("Waiting for your node ({e})");
            return;
        }
    };
    let epoch = now / em::MIX_EPOCH_MS;
    let t = now % em::MIX_EPOCH_MS;
    let Ok((dq, _, _)) = vault_keys_at(coin_index) else { return };
    let Some(coin_internal) = usdmd_node::btc_tx::txid_from_display_hex(&coin_txid) else { return };

    if let Some(cur) = plan.current.as_mut() {
        if cur.signed {
            // the round is signed: it is done when its transaction confirms (the first output's deposit address sees it)
            let confs = cur.creds.first().and_then(|c| coin_confs(&c.deposit_address, &cur.txid_hex)).unwrap_or(0);
            if confs >= 1 {
                plan.swaps.extend(cur.creds.iter().map(|c| c.swap_id.clone()));
                plan.rounds_done += 1;
                plan.coin = match (cur.change_index, cur.change_value, cur.change_vout) {
                    (Some(i), Some(v), Some(o)) => Some((cur.txid_hex.clone(), o, v, i)),
                    _ => None,
                };
                plan.current = None;
                plan.note = format!("Step {} done — {} private deposit(s) minting", plan.rounds_done, plan.swaps.len());
                if plan.coin.is_none() {
                    plan.status = "done".into();
                }
            } else if epoch > cur.epoch + 2 {
                // the coordinator never got it confirmed: the coin is still the user's; mix it again
                let ids: Vec<String> = cur.creds.iter().map(|c| c.swap_id.clone()).collect();
                expire_swaps(&ids);
                plan.current = None;
                plan.note = "That round did not reach Bitcoin; your coin is still yours — joining the next round".into();
            } else {
                plan.note = "Signed — waiting for Bitcoin to confirm the private deposit".into();
            }
            return;
        }
        if cur.epoch != epoch {
            let ids: Vec<String> = cur.creds.iter().map(|c| c.swap_id.clone()).collect();
            expire_swaps(&ids);
            plan.current = None;
            plan.note = "That round did not fill; your coin is still yours — joining the next round".into();
            return;
        }
        let Some(terms) = terms_of(cur) else { return };
        // the input's verdict
        if !cur.in_ok {
            match answer(&cur.in_hash_hex) {
                Some(Ok(())) => cur.in_ok = true,
                Some(Err(why)) => {
                    let ids: Vec<String> = cur.creds.iter().map(|c| c.swap_id.clone()).collect();
                    expire_swaps(&ids);
                    plan.current = None;
                    plan.note = format!("The round refused your coin ({why}); trying the next round");
                    return;
                }
                None if now.saturating_sub(cur.in_sent_ms) > 15_000 && t < em::MIX_INPUTS_END_MS => {
                    if let Ok(req) = hex::decode(&cur.in_req_hex) {
                        if let Ok(h) = send(&req) {
                            cur.in_hash_hex = h;
                            cur.in_sent_ms = now;
                        }
                    }
                }
                None => {}
            }
            plan.note = "Joining a private round with other people".into();
            return;
        }
        let view = views.iter().find(|v| v.terms.round_id == terms.round_id);
        let Some(view) = view else {
            plan.note = "Waiting for the other people in the round".into();
            return;
        };
        match view.phase {
            em::Phase::Outputs => {
                let Some((leaves, root, sig)) = view.record.clone() else { return };
                let window = em::MIX_OUTPUTS_END_MS.saturating_sub(8_000).saturating_sub(t);
                for c in cur.creds.iter_mut() {
                    if c.out_req_hex.is_empty() {
                        let Some(cred) = owner_of(&c.owner_hex) else { continue };
                        if em::check_record(&terms, &leaves, &root, &sig, &cred).is_none() {
                            plan.note = "The round's record does not hold your credential — your coin will not be signed".into();
                            return;
                        }
                        let Ok(spk) = hex::decode(&c.out_spk_hex) else { continue };
                        let Some(o) = em::prove_output(&terms, &leaves, &cred, &spk) else { continue };
                        c.out_req_hex = hex::encode(em::MixRequest::Output(o).encode(&terms.round_id));
                        let jitter = usdmd_node::cashout_ticket::fresh_entropy(8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))).unwrap_or(0);
                        c.send_at_ms = now + if window == 0 { 0 } else { jitter % window };
                    }
                    if c.out_hash_hex.is_empty() && now >= c.send_at_ms {
                        if let Ok(req) = hex::decode(&c.out_req_hex) {
                            if let Ok(h) = send(&req) {
                                c.out_hash_hex = h;
                            }
                        }
                    } else if !c.out_ok && !c.out_hash_hex.is_empty() {
                        match answer(&c.out_hash_hex) {
                            Some(Ok(())) => c.out_ok = true,
                            // our own re-send of an output already registered
                            Some(Err(why)) if why.contains("already redeemed") || why.contains("already registered") => c.out_ok = true,
                            Some(Err(_)) => c.out_hash_hex.clear(),
                            None => {}
                        }
                    }
                }
                plan.note = "Registering your private deposits".into();
            }
            em::Phase::Signing | em::Phase::Broadcast => {
                let Some(tx) = view.tx.clone() else { return };
                let outs: Vec<Vec<u8>> = cur.creds.iter().filter_map(|c| hex::decode(&c.out_spk_hex).ok()).collect();
                let change = match (cur.change_index, cur.change_value) {
                    (Some(i), Some(v)) => vault_keys_at(i).ok().map(|(_, spk, _)| (spk, v)),
                    _ => None,
                };
                let Some(idx) = em::may_sign(&terms, &tx, (&coin_internal, coin_vout, coin_value), &outs, change.as_ref().map(|(s, v)| (s.as_slice(), *v))) else {
                    plan.note = "The round's transaction left out one of your deposits — your Bitcoin was not signed over (it stays yours)".into();
                    return;
                };
                let Some(sig) = em::sign_round_input(&tx, idx, &dq) else { return };
                let req = em::MixRequest::Sign { txid: coin_internal, vout: coin_vout, sig }.encode(&terms.round_id);
                if send(&req).is_ok() {
                    cur.signed = true;
                    cur.txid_hex = usdmd_node::btc_tx::txid_display_hex(&tx.txid());
                    cur.change_vout = change.as_ref().and_then(|(s, v)| tx.outputs.iter().position(|o| &o.script_pubkey == s && o.value_sats == *v)).map(|i| i as u32);
                    plan.note = "Signed — waiting for Bitcoin to confirm the private deposit".into();
                }
            }
            em::Phase::Inputs => plan.note = "Waiting for the other people in the round".into(),
        }
        return;
    }

    // a new round: inputs open with at least 15 s left
    if t + 15_000 > em::MIX_INPUTS_END_MS {
        plan.note = "Waiting for the next private round to open".into();
        return;
    }
    let Some(v0) = views.iter().find(|v| v.epoch == epoch) else {
        plan.note = "Waiting for a private round to be announced".into();
        return;
    };
    let Some((terms, k)) = leading_digit(&v0.terms.coordinator_pk, v0.terms.fee_rate_sat_vb, epoch, coin_value) else {
        plan.left_in_vault = coin_value;
        plan.status = "done".into();
        plan.note = "Done. Under 0.0001 BTC stays in your Bitcoin vault".into();
        return;
    };
    // ⭐ §18.14: a private SAT buy's deposits mint Bitcoin notes atom for atom, so it reads no price; a plain private deposit mints USDm at the mark
    let usdm = if plan.then_buy.is_some() {
        0.0
    } else {
        let (Ok((price, scale, _)), Ok(backing)) = (price_mark_for("BTC"), mint_ratio_bps()) else {
            plan.note = "Waiting for the chain's Bitcoin price".into();
            return;
        };
        usdm_for_unit(terms.denom, price, scale, backing)
    };
    let mut creds = Vec::with_capacity(k);
    for _ in 0..k {
        let Some(cred) = em::Credential::fresh() else { return };
        let started = if plan.then_buy.is_some() { coin_deposit_start("BTC", terms.denom.saturating_sub(SWEEP_FEE_SATS)) } else { buy_swap_inner("BTC".into(), usdm, false) };
        let swap = match started {
            Ok(s) => s,
            Err(e) => {
                plan.note = format!("Waiting for the reserve ({e})");
                return;
            }
        };
        let (Some(id), Some(addr)) = (swap["swap_id"].as_str(), swap["deposit_address"].as_str()) else { return };
        let Some((_, spk)) = usdmd_node::btc_tx::script_pubkey_for_address(addr) else { return };
        creds.push((cred, MixCred { swap_id: id.to_string(), deposit_address: addr.to_string(), out_spk_hex: hex::encode(&spk), ..MixCred::default() }));
    }
    let change_value = terms.change_for(coin_value, k).ok().flatten();
    let change_index = change_value.map(|_| vault_next_index(&read_cashouts()));
    let change_spk = match change_index {
        Some(i) => match vault_keys_at(i) {
            Ok((_, spk, _)) => spk,
            Err(_) => return,
        },
        None => Vec::new(),
    };
    let only: Vec<em::Credential> = creds.iter().map(|(c, _)| c.clone()).collect();
    let Some(reg) = em::sign_input_registration(&terms, &coin_internal, coin_vout, &only, &change_spk, &dq) else { return };
    let req = em::MixRequest::Input(reg).encode(&terms.round_id);
    let hash = match send(&req) {
        Ok(h) => h,
        Err(e) => {
            let ids: Vec<String> = creds.iter().map(|(_, m)| m.swap_id.clone()).collect();
            expire_swaps(&ids);
            plan.note = format!("Could not reach the round right now ({e}); retrying");
            return;
        }
    };
    plan.current = Some(MixRound {
        epoch,
        denom: terms.denom,
        fee_rate: terms.fee_rate_sat_vb,
        coordinator_pk_hex: hex::encode(&terms.coordinator_pk),
        creds: creds.into_iter().map(|(c, mut m)| {
            m.owner_hex = owner_hex(&c);
            m
        }).collect(),
        change_index,
        change_value,
        change_vout: None,
        in_req_hex: hex::encode(&req),
        in_hash_hex: hash,
        in_ok: false,
        in_sent_ms: now,
        signed: false,
        txid_hex: String::new(),
    });
    plan.note = format!("Making your deposit private · step {} · about 2 min", plan.rounds_done + 1);
}

fn plan_json(p: &MixPlan, swaps: &[SwapRec]) -> serde_json::Value {
    let minting = p.swaps.iter().filter(|sid| swaps.iter().any(|s| &s.swap_id == *sid && unminted(&s.status))).count();
    let receive = vault_keys_at(p.receive_index).map(|(_, _, a)| a).unwrap_or_default();
    serde_json::json!({
        "plan_id": p.plan_id,
        "status": p.status,
        "note": p.note,
        "receive_address": receive,
        "rounds_done": p.rounds_done,
        "deposits": p.swaps.len(),
        "minting": minting,
        "minted": p.swaps.iter().filter(|sid| swaps.iter().any(|s| &s.swap_id == *sid && s.status == "minted")).count(),
        "mixing_btc": p.coin.as_ref().map(|c| c.2 as f64 / 1e8),
        "left_in_vault_btc": p.left_in_vault as f64 / 1e8,
        "in_round": p.current.as_ref().map(|c| serde_json::json!({ "unit_btc": c.denom as f64 / 1e8, "units": c.creds.len(), "signed": c.signed })),
    })
}

/// Start: a fresh vault address for the user to send Bitcoin to; the wallet makes the deposit private on its own.
pub(crate) fn wallet_mix_start_blocking() -> Result<serde_json::Value, String> {
    let key_id_hex = current_key_id_hex().ok_or("no wallet open")?;
    let index = vault_next_index(&read_cashouts());
    let (_, _, address) = vault_keys_at(index)?;
    let created = now_ms();
    let plan = MixPlan {
        plan_id: format!("MIX-{}", &hex::encode(blake3::hash(format!("{key_id_hex}/{created}/{index}").as_bytes()).as_bytes())[..12].to_uppercase()),
        key_id_hex,
        created_ms: created,
        receive_index: index,
        status: "awaiting_funds".into(),
        note: "Waiting for your Bitcoin".into(),
        ..MixPlan::default()
    };
    let mut all = read_mixes();
    all.push(plan.clone());
    write_mixes(&all);
    Ok(serde_json::json!({ "plan": plan_json(&plan, &read_swaps()), "address": address }))
}

/// A coin swap's PRIVATE Bitcoin leg (Auto-OPSEC on): an ordinary private deposit plan whose minted USDm the coin-swap runner
/// then cashes out to `to` at `payout_to` — the privacy step the deposit owes is never skipped for a swap.
pub(crate) fn coin_swap_mix_start(to: &str, payout_to: &str) -> Result<serde_json::Value, String> {
    let r = wallet_mix_start_blocking()?;
    let id = r.get("plan").and_then(|p| p.get("plan_id")).and_then(|v| v.as_str()).ok_or("the private deposit plan has no id")?.to_string();
    let mut all = read_mixes();
    if let Some(p) = all.iter_mut().find(|p| p.plan_id == id) {
        p.then_pay = Some((to.to_string(), payout_to.to_string()));
    }
    write_mixes(&all);
    Ok(r)
}

/// A Buy SAT's PRIVATE Bitcoin leg (Auto-OPSEC on): an ordinary private deposit plan whose minted USDm becomes one sealed SAT
/// order at maximum-price bucket `bucket` — the privacy step the deposit owes is never skipped for a buy.
pub(crate) fn sat_buy_mix_start(bucket: usize) -> Result<serde_json::Value, String> {
    let r = wallet_mix_start_blocking()?;
    let id = r.get("plan").and_then(|p| p.get("plan_id")).and_then(|v| v.as_str()).ok_or("the private deposit plan has no id")?.to_string();
    let mut all = read_mixes();
    if let Some(p) = all.iter_mut().find(|p| p.plan_id == id) {
        p.then_buy = Some(bucket);
        p.note = "Waiting for your Bitcoin · it is made private, then buys SAT".into();
    }
    write_mixes(&all);
    Ok(r)
}

/// The Buy SAT plans whose every mixed deposit has minted and whose orders are not yet placed: `(plan id, each minted Bitcoin note's atoms, bucket)`
/// — each CLAIMED here (`bought`), so an overlapping tick never places it twice. Advances the open Buy SAT plans first.
pub(crate) fn sat_buy_mix_ready() -> Vec<(String, Vec<u64>, usize)> {
    let Some(kid) = current_key_id_hex() else { return Vec::new() };
    if !read_mixes().iter().any(|p| p.then_buy.is_some() && !p.bought && p.key_id_hex == kid) {
        return Vec::new();
    }
    let _ = wallet_mix_progress_blocking();
    let mut all = read_mixes();
    let swaps = read_swaps();
    let mut ready = Vec::new();
    for p in all.iter_mut().filter(|p| p.then_buy.is_some() && p.status == "done" && !p.bought && p.key_id_hex == kid) {
        let mine: Vec<&SwapRec> = swaps.iter().filter(|s| p.swaps.contains(&s.swap_id)).collect();
        if mine.is_empty() || mine.iter().any(|s| s.status != "minted") {
            continue; // the deposits are still minting
        }
        p.bought = true;
        ready.push((p.plan_id.clone(), mine.iter().filter_map(|s| s.coin_atomic).collect(), p.then_buy.unwrap_or(usdmd_node::defi_clear::DEFAULT_BUCKET)));
    }
    write_mixes(&all);
    ready
}

/// The plain-language outcome of a Buy SAT plan's order.
pub(crate) fn sat_buy_mix_note(plan_id: &str, note: String) {
    let mut all = read_mixes();
    if let Some(p) = all.iter_mut().find(|p| p.plan_id == plan_id) {
        p.note = note;
    }
    write_mixes(&all);
}

/// The coin-swap runner's private-deposit step: advance this wallet's coin-swap plans (their deposits mint inside the
/// progress), then cash a finished plan's minted USDm out to its target once — whatever screen is open.
pub(crate) fn coin_swap_mix_tick() {
    let Some(kid) = current_key_id_hex() else { return };
    if !read_mixes().iter().any(|p| p.then_pay.is_some() && !p.cashed && p.key_id_hex == kid) {
        return;
    }
    let _ = wallet_mix_progress_blocking();
    let mut all = read_mixes();
    let swaps = read_swaps();
    for p in all.iter_mut().filter(|p| p.then_pay.is_some() && p.status == "done" && !p.cashed && p.key_id_hex == kid) {
        let mine: Vec<&SwapRec> = swaps.iter().filter(|s| p.swaps.contains(&s.swap_id)).collect();
        if mine.iter().any(|s| s.status != "minted") {
            continue; // the deposits are still minting
        }
        let Some((asset, payout)) = p.then_pay.clone() else { continue };
        let total: f64 = mine.iter().map(|s| s.usdm_out).sum();
        let amount = total * (1.0 - FEE_BPS_CASH as f64 / 10_000.0) - P2P_FEE_ATOMIC as f64 / 1e8;
        let amount = if asset == "XMR" { amount.floor() } else { amount };
        p.cashed = true; // claimed before it runs: an overlapping tick never cashes out twice
        let sent = if mine.is_empty() || amount <= 0.0 {
            Err("nothing minted to swap".to_string())
        } else {
            crate::wallet_cash_out_blocking(amount, asset.clone(), payout.clone(), !auto_opsec_on())
        };
        p.note = match sent {
            Ok(_) => format!("Swapped: the private deposit's USDm is cashing out to {asset}"),
            Err(e) => format!("The private deposit minted, but the {asset} cash-out did not start ({e}) — your USDm is safe in this wallet; cash it out from Sell"),
        };
    }
    write_mixes(&all);
}

/// Progress: advance every open plan one step and answer every plan in plain language.
pub(crate) fn wallet_mix_progress_blocking() -> Result<serde_json::Value, String> {
    let kid = current_key_id_hex().ok_or("no wallet open")?;
    let mut all = read_mixes();
    for i in 0..all.len() {
        if all[i].key_id_hex == kid && all[i].status != "done" {
            let mut p = all[i].clone();
            advance_mix(&mut p);
            all[i] = p;
            write_mixes(&all); // at once, so the next plan's fresh vault index sees this one's
        }
    }
    // ⭐ THE MIXED DEPOSITS MINT. Each finished round leaves its ladder units at their deposit addresses as ordinary swaps; the
    // honest auto-mint (`wallet_try_mint`: the node mints only once the real deposit has matured) runs for every one of them
    // on every poll, whatever screen is open — before, only the Buy screen's single-swap poll called it, so a mixed deposit
    // sat unminted (MEASURED in the shipped add-money flow: "1 step done · 1 private deposit minting", home balance 0.00).
    let swaps = read_swaps();
    for p in all.iter().filter(|p| p.key_id_hex == kid) {
        for sid in &p.swaps {
            if swaps.iter().any(|s| &s.swap_id == sid && unminted(&s.status)) {
                let _ = crate::wallet_try_mint_blocking(sid.clone()); // a refusal or "not yet" leaves it for the next poll
            }
        }
    }
    let swaps = read_swaps();
    let rows: Vec<serde_json::Value> = all.iter().filter(|p| p.key_id_hex == kid).rev().map(|p| plan_json(p, &swaps)).collect();
    Ok(serde_json::json!({ "plans": rows }))
}

/// A swap whose deposit has not minted yet (nor been redeemed or expired).
fn unminted(status: &str) -> bool {
    !matches!(status, "minted" | "redeemed" | "expired")
}

/// The dollars-first preview for `btc`: the ladder units it becomes, the USDm they mint, the rounds and the minutes, what
/// stays in the vault. Fees shown before the user sends anything.
pub(crate) fn wallet_mix_quote_blocking(btc: f64) -> Result<serde_json::Value, String> {
    if !(btc > 0.0) {
        return Err("enter a Bitcoin amount".into());
    }
    let mut left = (btc * 1e8).round() as u64;
    // ⭐ §18.14: a private SAT buy needs this preview with no price mark at all, so a missing mark only leaves the USDm figure at 0
    let mark = price_mark_for("BTC").ok().zip(mint_ratio_bps().ok());
    let fee_rate = 2u64; // the quote's assumption; the round's own rate is the coordinator's (the Bitcoin mempool's)
    let (mut usdm, mut units, mut rounds, mut fees) = (0f64, 0usize, 0u32, 0u64);
    while let Some((terms, k)) = leading_digit(&[0u8; 32], fee_rate, 0, left) {
        let change = terms.change_for(left, k).ok().flatten();
        let fee = terms.input_fee(k, change.is_some());
        if let Some(((price, scale, _), backing)) = mark {
            usdm += usdm_for_unit(terms.denom, price, scale, backing) * k as f64;
        }
        units += k;
        rounds += 1;
        fees += fee;
        left = change.unwrap_or(0);
        if rounds > 16 {
            break;
        }
    }
    Ok(serde_json::json!({
        "usdm": usdm, "deposits": units, "rounds": rounds, "minutes": rounds as f64 * (em::MIX_EPOCH_MS as f64 / 60_000.0),
        "bitcoin_fees_btc": fees as f64 / 1e8, "left_in_vault_btc": left as f64 / 1e8,
    }))
}

#[cfg(test)]
mod mix_client_pins {
    use super::*;

    /// One round takes one whole decimal digit of the coin: 0.37 BTC mixes 3 × 0.1 first, then 7 × 0.01 from the change, and
    /// what is under the smallest unit (with its fee) stays in the vault.
    #[test]
    fn a_coin_mixes_one_decimal_digit_per_round_down_to_the_smallest_ladder_unit() {
        let pk = vec![7u8; 32];
        let (t, k) = leading_digit(&pk, 2, 5, 37_000_000).unwrap();
        assert_eq!((t.denom, k), (10_000_000, 3));
        let change = t.change_for(37_000_000, 3).unwrap().unwrap();
        let (t2, k2) = leading_digit(&pk, 2, 5, change).unwrap();
        assert_eq!((t2.denom, k2), (1_000_000, 6), "7 units less the first round's fee leaves 6 whole units of 0.01");
        let (t9, k9) = leading_digit(&pk, 2, 5, 99_990_000).unwrap();
        assert_eq!((t9.denom, k9), (10_000_000, 9), "a 9 digit fits one round");
        assert!(leading_digit(&pk, 2, 5, 9_000).is_none(), "under the smallest unit nothing mixes");
        assert_eq!(t.round_id, em::RoundTerms::for_epoch(pk.clone(), 10_000_000, 2, 5).unwrap().round_id, "the wallet derives the round id");
    }

    #[test]
    fn a_ladder_unit_mints_its_priced_value_over_the_backing_less_the_sweep_fee_and_a_margin() {
        // price: 1 sat = 0.0007 USDm-atomic·scale → 1 BTC = $70,000 at scale 1e8 (price = 70,000 × 1e8 atomic per 1e8 sats × scale/1e8)
        let (price, scale) = (70_000u128 * 100_000_000, 100_000_000u128);
        let usdm = usdm_for_unit(100_000_000, price, scale, 15_000);
        let exact = (100_000_000 - SWEEP_FEE_SATS) as f64 * 70_000.0 / 1e8 / 1.5;
        assert!(usdm <= exact * 0.97 + 0.01 && usdm >= exact * 0.97 - 0.02, "{usdm} vs {exact}");
        assert_eq!((usdm * 100.0).fract().abs() < 1e-6, true, "whole cents");
    }

    #[test]
    fn a_credentials_one_time_keys_round_trip_through_the_plan_file() {
        let c = em::Credential::fresh().unwrap();
        let back = owner_of(&owner_hex(&c)).unwrap();
        let terms = em::RoundTerms::for_epoch(vec![1u8; 32], 100_000, 2, 1).unwrap();
        assert_eq!(back.cm(&terms), c.cm(&terms));
        assert!(owner_of("00").is_none());
    }
}

// ═══════════════════════════════ ⭐ §BR-8 B8-b — THE REMIXER (docs/BR-8-LAUNCH-CROWD-SPEC-20261029.md §1) ═══════════════════════════════
//
// A validator's wallet with "Remix to widen private rounds" on keeps its Bitcoin cycling through the same rounds users take:
// every confirmed coin in its vault (a cash-out piece that arrived, a mix change) joins an entry round into its own fresh
// co-signed deposits — exactly a user's plan, so its registrations are byte-shape-identical to a user's — and once those
// deposits mint, the USDm is cashed back out through the ordinary pieces (the privacy delay applies) to fresh vault
// addresses, which feed the next round: real cover on both edges. Paid through the bonders' yield, never per round (a
// per-round claim would tell the coordinator which inputs and outputs are a remixer's). Off by default.

pub(crate) fn remix_on() -> bool {
    std::fs::read_to_string(node_data_dir().join("remix")).is_ok_and(|s| s.trim() == "on")
}

/// The vault addresses a coin may sit at outside any open plan: the vault indexes cash-out pieces paid to.
fn vault_piece_indexes() -> Vec<u32> {
    let mut v: Vec<u32> = read_cashouts().iter().flat_map(|p| p.pieces.iter().filter(|c| c.status == "redeemed").filter_map(|c| c.vault_index)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// One remixer step: start a plan for a free vault coin (one open remix plan at a time), and cash a finished plan's minted
/// deposits back out to the vault.
pub(crate) fn remix_tick() {
    if !remix_on() {
        return;
    }
    let Some(kid) = current_key_id_hex() else { return };
    let mut all = read_mixes();
    let busy: Vec<u32> = all.iter().flat_map(|p| [Some(p.receive_index), p.coin.as_ref().map(|c| c.3)]).flatten().collect();
    if !all.iter().any(|p| p.remix && p.status != "done" && p.key_id_hex == kid) {
        for index in vault_piece_indexes().into_iter().filter(|i| !busy.contains(i)) {
            let Ok((_, _, addr)) = vault_keys_at(index) else { continue };
            let Some((txid, vout, value, confs)) = best_coin(&addr) else { continue };
            if confs < 1 || value < usdmd_node::peg_pool::PAYOUT_DENOMS[0] {
                continue;
            }
            let created = now_ms();
            all.push(MixPlan {
                plan_id: format!("REMIX-{}", &hex::encode(blake3::hash(format!("{kid}/{created}/{index}").as_bytes()).as_bytes())[..12].to_uppercase()),
                key_id_hex: kid.clone(),
                created_ms: created,
                receive_index: index,
                coin: Some((txid, vout, value, index)),
                status: "mixing".into(),
                note: "Remixing a vault coin into a private round".into(),
                remix: true,
                ..MixPlan::default()
            });
            break;
        }
    }
    let swaps = read_swaps();
    for p in all.iter_mut().filter(|p| p.remix && p.status == "done" && !p.cashed && p.key_id_hex == kid) {
        let mine: Vec<&SwapRec> = swaps.iter().filter(|s| p.swaps.contains(&s.swap_id)).collect();
        if mine.is_empty() {
            p.cashed = true; // nothing minted (the coin was under one unit): nothing to cash out
            continue;
        }
        if mine.iter().any(|s| s.status != "minted") {
            continue; // the deposits are still minting
        }
        let total: f64 = mine.iter().map(|s| s.usdm_out).sum();
        if let Ok(plan) = plan_cash_out(total, "BTC", "", false) {
            let mut cash = read_cashouts();
            cash.push(plan.clone());
            write_cashouts(&cash);
            let mut plan = plan;
            advance_cash_out(&mut plan);
            p.cashed = true;
            p.note = "Remixed: the minted deposits are cashing back out to the vault".into();
        }
    }
    write_mixes(&all);
}

pub(crate) fn remix_status() -> Result<serde_json::Value, String> {
    let open = read_mixes().iter().filter(|p| p.remix && p.status != "done").count();
    Ok(serde_json::json!({ "on": remix_on(), "open_rounds": open }))
}

pub(crate) fn wallet_set_remix_blocking(on: bool) -> Result<serde_json::Value, String> {
    let dir = node_data_dir();
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("remix"), if on { "on" } else { "off" }).map_err(|e| format!("could not save the setting: {e}"))?;
    Ok(serde_json::json!({ "on": remix_on() }))
}

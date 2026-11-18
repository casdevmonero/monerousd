// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ IONSWAP POOLS — the wallet's half (docs/IONSWAP-POOLS-SPEC-20261110.md §13; lane goods, 2026-11-11).
//!
//! - **List** (`ion_pools`) and **one pool** (`ion_pool`): this wallet's own node's copy of the pools (two balances, a
//!   share count and a price each, public once a block). No server is asked which pool a person looks at.
//! - **Position** (`ion_position`): what THIS wallet holds for a pool, summed from its own notes: the pool's shares, the
//!   token, and USDm. Nothing is asked of anyone.
//! - **A swap** (`ion_swap`): one token for another in ONE order: a sale whose USDm the chain spends in the second
//!   token's pool, each leg with this wallet's own floor.
//! - **An order** (`ion_order`): buy, sell, add liquidity, REMOVE liquidity, or launch. The wallet spends one of its own
//!   notes for each asset the order brings (the public-amount burn every node already verifies: the creation fee's for
//!   USDm, the bond's for a token or a share note), bound to this order's own words, and seals the part of the payout
//!   notes only it can open. The node pools the order; the block after the one that carries it pays it, and the payout
//!   arrives as ordinary notes this wallet's scan finds and a restore from the seed finds again.
//!
//! WITHDRAWABLE: a share is a note in this wallet. Removing liquidity spends that note in an order nobody can refuse.
//!
//! BORROWED: Uniswap v2's add and remove as the provider's own acts; Penumbra's swap whose output is claimed privately.
//! DIGITAL-CASH-PRIVACY-REVIEWED: an order's sizes are public by the pool lane's own rule; its inputs are this wallet's
//! private notes, its payout opening and locators are fresh for every order, and nothing here is sent to anyone but this
//! wallet's own node.

use super::*;
use usdm_decider::whir_rec_block as wr;
use usdmd_node::ion_pool_tx as it;

/// A lock this module reads through: a poisoned lock still holds the same data, so it is read as it stands.
fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build()
}

fn token_of(token_hex: &str) -> Result<[u8; 32], String> {
    hex::decode(token_hex.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| "a pool is named by its token's id (64 hex characters)".to_string())
}

fn node_json(route: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    agent()
        .post(&format!("{}{route}", node_url()))
        .send_json(body)
        .map_err(|e| format!("your node did not answer: {}", node_refusal(e)))
        .and_then(|r| r.into_json().map_err(|e| format!("your node's answer does not read: {e}")))
}

/// Every pool this wallet's node holds, the deepest first; `q` narrows by symbol, name or the start of a token's id.
pub(crate) fn pools_blocking(q: String, skip: u64, max: u64) -> Result<serde_json::Value, String> {
    node_json("/ion/pools", serde_json::json!({ "q": q, "skip": skip, "max": max }))
}

/// One pool, by its token's id; when no pool is open for it, what the chain records of the token itself.
pub(crate) fn pool_blocking(token_hex: String) -> Result<serde_json::Value, String> {
    let token = token_of(&token_hex)?;
    let mut r = node_json("/ion/pool", serde_json::json!({ "token": hex::encode(token) }))?;
    if r.get("found").and_then(|v| v.as_bool()) != Some(true) {
        if let Ok(a) = node_json("/dir/asset", serde_json::json!({ "id": hex::encode(token) })) {
            if a.get("found").and_then(|v| v.as_bool()) == Some(true) {
                r["asset"] = serde_json::json!({ "symbol": a.get("symbol"), "name": a.get("name") });
            }
        }
    }
    Ok(r)
}

/// What this wallet holds for a pool: its shares, the token, and USDm, in atomic units (decimal strings), and the size
/// of each share note (a removal hands back one note at a time).
pub(crate) fn position_blocking(token_hex: String) -> Result<serde_json::Value, String> {
    let token = token_of(&token_hex)?;
    // spec §14: the unlock dates the pool's lock table lists, read first from this wallet's node; every locked share of
    // this pool is under one of them, so this wallet's locked notes are found by their tags with no other ask
    let weeks: Vec<u32> = node_json("/ion/pool", serde_json::json!({ "token": hex::encode(token) }))
        .ok()
        .and_then(|r| r.pointer("/pool/locks").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e.get("week").and_then(serde_json::Value::as_u64).and_then(|w| u32::try_from(w).ok()))
        .collect();
    let share_tag = it::ion_tag(&token, it::IonAsset::Share);
    let token_tag = it::ion_tag(&token, it::IonAsset::Token);
    let s = locked(&SCAN);
    let st = s.as_ref().ok_or("the wallet has not scanned yet")?;
    let live = |n: &&OwnedNote| !st.spent.contains(&(n.amount, n.seed));
    let sum = |tag: [u64; 3]| -> u128 { st.owned.iter().filter(live).filter(|n| n.asset == tag).map(|n| u128::from(n.amount)).sum() };
    let mut share_notes: Vec<u64> = st.owned.iter().filter(live).filter(|n| n.asset == share_tag && n.amount > 0).map(|n| n.amount).collect();
    share_notes.sort_unstable_by(|a, b| b.cmp(a));
    // an order spends ONE note of each asset it brings, so a page also needs the largest single note of each
    // (the largest note SPENDABLE NOW: a change no block carries yet is held, and counted above, but cannot pay an order)
    let proven: HashSet<[u8; 32]> = PROVEN_SPENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let largest = |tag: [u64; 3]| -> u64 {
        st.owned.iter().filter(|n| n.asset == tag && spendable_now(&st.spent, &st.pending_change, &proven, n.amount, n.seed, &n.nf)).map(|n| n.amount).max().unwrap_or(0)
    };
    // this wallet's locked shares, by unlock date (one entry for each date it holds any of)
    let locked: Vec<serde_json::Value> = weeks
        .iter()
        .filter_map(|w| {
            let tag = it::ion_tag(&token, it::IonAsset::Locked(*w));
            let held = sum(tag);
            let mut notes: Vec<u64> = st.owned.iter().filter(live).filter(|n| n.asset == tag && n.amount > 0).map(|n| n.amount).collect();
            notes.sort_unstable_by(|a, b| b.cmp(a));
            (held > 0).then(|| {
                serde_json::json!({
                    "week": w,
                    "unlock_secs": it::lock_week_start_secs(*w),
                    "unlock_date": week_date(*w),
                    "shares": held.to_string(),
                    "notes": notes.iter().map(u64::to_string).collect::<Vec<_>>(),
                })
            })
        })
        .collect();
    Ok(serde_json::json!({
        "locked": locked,
        "shares": sum(share_tag).to_string(),
        "token": sum(token_tag).to_string(),
        "usdm": sum([0, 0, 0]).to_string(),
        "token_note_max": largest(token_tag).to_string(),
        "usdm_note_max": largest([0, 0, 0]).to_string(),
        "share_notes": share_notes.iter().map(u64::to_string).collect::<Vec<_>>(),
    }))
}

/// ⭐ THE TOKEN'S DESCRIPTOR WORDS AND WHETHER THIS WALLET'S KEY CREATED IT. A token's id binds its creator's key
/// (`asset_tx::asset_id_of_creator`), so this wallet created `token` exactly when the descriptor the chain's directory
/// holds, under this wallet's own spend key, reproduces the id. Read from this wallet's own node; nothing is trusted from
/// it (a wrong record reproduces no id). `(kind, symbol, name, logo, this wallet created it)`.
fn creator_facts(token: &[u8; 32]) -> Result<(usdmd_node::asset_tx::AssetKind, String, String, [u8; 32], bool), String> {
    let a = node_json("/dir/asset", serde_json::json!({ "id": hex::encode(token) }))?;
    if a.get("found").and_then(|v| v.as_bool()) != Some(true) {
        return Err("this token is not in the chain's directory".into());
    }
    let text = |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let kind = if text("kind") == "nft" { usdmd_node::asset_tx::AssetKind::Nft } else { usdmd_node::asset_tx::AssetKind::Token };
    let mut logo = [0u8; 32];
    if let Ok(b) = hex::decode(text("logo")) {
        if b.len() == 32 {
            logo.copy_from_slice(&b);
        }
    }
    let spend_pk = {
        let g = locked(&WALLET);
        g.as_ref().ok_or_else(|| "no wallet open".to_string())?.spend_pk.clone()
    };
    let (symbol, name) = (text("symbol"), text("name"));
    let mine = usdmd_node::asset_tx::asset_id_of_creator(kind, &symbol, &name, logo, &spend_pk) == *token;
    Ok((kind, symbol, name, logo, mine))
}

/// Did this wallet's key create `token`? `false` when it did not or when the chain's record cannot be read.
pub(crate) fn is_creator(token_hex: &str) -> bool {
    token_of(token_hex).ok().and_then(|t| creator_facts(&t).ok()).is_some_and(|f| f.4)
}

/// ⭐ THE CREATOR TAKES THE FEE PARTS THE POOL HOLDS FOR IT: an order of kind `ION_CLAIM`, signed by this wallet's key
/// as the token's creator. It burns one atomic unit of USDm (0.00000001) beside the network fee, which comes back with
/// what the pool pays. Refused here, with nothing spent, when this wallet's key did not create the token.
pub(crate) fn claim_blocking(token_hex: String) -> Result<serde_json::Value, String> {
    order_blocking(it::ION_CLAIM, token_hex, 0, 1, 0, 0)
}

/// ⭐ THE POOL ORDERS THIS RUN OF THE WALLET SENT, for the Activity page: what each was, and what it has been PAID so
/// far. Kept in memory only, the newest [`SENT_KEPT`]: an order is paid a block or two after it is sent, so this is a
/// view of what is in flight, never a record anything depends on (a wallet opened again shows its balances, which the
/// chain decides, and an empty list here). Nothing is written to disk: a file naming which public orders were this
/// wallet's would tie them to this device for whoever reads it later.
/// What an order was paid is read from this wallet's OWN notes: every payout note of an order is owned under the
/// opening the order named (fresh for every order), so the notes with that opening are exactly its payouts.
#[derive(Clone)]
struct SentOrder {
    /// Which wallet sent it (a digest of its spend key), so a second wallet opened in the same run sees none of the first's.
    wallet: [u8; 32],
    id: [u8; 32],
    kind: u8,
    token: [u8; 32],
    hop: [u8; 32],
    x: u64,
    y: u64,
    shares: u64,
    /// spec §14: the lock weeks the order named (0 on every order but a removal, a lock or an unlock)
    lock_from: u32,
    lock_until: u32,
    opening: Digest4,
    at: u64,
}
/// O1-FOOTPRINT-REVIEWED: at most [`SENT_KEPT`] entries of about 150 bytes, in memory, the oldest dropped first.
static SENT: std::sync::Mutex<Vec<SentOrder>> = std::sync::Mutex::new(Vec::new());
const SENT_KEPT: usize = 24;
/// How long an order with no payout in the wallet yet is called "in flight" when a later order finds no note to spend:
/// an order is paid a block or two after it is sent, minutes at the very most, so past this the answer is the plain one.
const ORDER_IN_FLIGHT_SECS: u64 = 180;

fn wallet_mark(spend_pk: &[u8]) -> [u8; 32] {
    *usdmd_node::hash::Hash32::hash(spend_pk).as_bytes()
}

/// The pool orders this run of the wallet sent, newest first, each with the notes it has been paid (by asset: the
/// pool's token, USDm, the pool's shares, or a swap's second token). `settled` is true once at least one payout note
/// of the order is in this wallet.
pub(crate) fn orders_blocking() -> Result<serde_json::Value, String> {
    let me = {
        let g = locked(&WALLET);
        wallet_mark(&g.as_ref().ok_or_else(|| "no wallet open".to_string())?.spend_pk)
    };
    let sent: Vec<SentOrder> = locked(&SENT).iter().filter(|o| o.wallet == me).cloned().collect();
    let s = locked(&SCAN);
    let st = s.as_ref().ok_or("the wallet has not scanned yet")?;
    let orders: Vec<serde_json::Value> = sent
        .iter()
        .rev()
        .map(|o| {
            let name = |tag: [u64; 3]| {
                if tag == [0, 0, 0] {
                    "usdm"
                } else if tag == it::ion_tag(&o.token, it::IonAsset::Token) {
                    "token"
                } else if tag == it::ion_tag(&o.token, it::IonAsset::Share) {
                    "share"
                } else if o.lock_until != 0 && tag == it::ion_tag(&o.token, it::IonAsset::Locked(o.lock_until)) {
                    // a lock that was taken: the shares came back locked until the new date
                    "locked"
                } else if o.lock_from != 0 && tag == it::ion_tag(&o.token, it::IonAsset::Locked(o.lock_from)) {
                    // the shares the order handed in, handed back as they were (too early, or a date off the grid)
                    "locked_back"
                } else if o.hop != [0u8; 32] && tag == it::ion_tag(&o.hop, it::IonAsset::Token) {
                    "hop_token"
                } else {
                    "other"
                }
            };
            let paid: Vec<serde_json::Value> =
                st.owned.iter().filter(|n| n.opening == o.opening).map(|n| serde_json::json!({ "asset": name(n.asset), "atomic": n.amount.to_string() })).collect();
            serde_json::json!({
                "order_id": hex::encode(o.id),
                "kind": o.kind,
                "token": hex::encode(o.token),
                "hop": if o.hop == [0u8; 32] { String::new() } else { hex::encode(o.hop) },
                "x": o.x.to_string(),
                "y": o.y.to_string(),
                "shares": o.shares.to_string(),
                "lock_from": o.lock_from,
                "lock_until": o.lock_until,
                "lock_from_date": if o.lock_from == 0 { String::new() } else { week_date(o.lock_from) },
                "lock_until_date": if o.lock_until == 0 { String::new() } else { week_date(o.lock_until) },
                "at": o.at,
                "settled": !paid.is_empty(),
                "paid": paid,
            })
        })
        .collect();
    Ok(serde_json::json!({ "orders": orders }))
}

/// The 32 bytes a locator clue is made of, for this wallet's own locator `(domain, j)`: `locator ‖ salt ‖ hint`. The node
/// expands them into the clue this wallet derives for itself (`own_note_clue`), so a payout is found where a change is.
fn locator_word(loc_sk: &[u8; 32], domain: &str, j: u64) -> [u8; 32] {
    let salt = usdmd_node::oli::address_salt(loc_sk, domain, j);
    let hint = usdmd_node::oli::address_index_hint(loc_sk, &salt, j);
    let mut w = [0u8; 32];
    w[..usdmd_node::oli::LOC_BYTES].copy_from_slice(&usdmd_node::oli::locator_at(loc_sk, domain, j));
    w[usdmd_node::oli::LOC_BYTES..usdmd_node::oli::LOC_BYTES + 8].copy_from_slice(&salt);
    w[usdmd_node::oli::LOC_BYTES + 8..].copy_from_slice(&hint);
    w
}

/// One order with no second pool (every kind but a swap): [`order_hop_blocking`].
pub(crate) fn order_blocking(kind: u8, token_hex: String, x: u64, y: u64, shares: u64, min_out: u64) -> Result<serde_json::Value, String> {
    order_hop_blocking(kind, token_hex, x, y, shares, min_out, [0u8; 32], 0)
}

/// ⭐ ONE TOKEN FOR ANOTHER, IN ONE ORDER (the swap): a sale of `x` of `from` whose USDm the chain itself spends on `to` in
/// `to`'s pool (`ion_pool_tx::IonOrderCore::hop`). Two floors, both this wallet's: `min_usdm` is the least USDm the
/// sale accepts (below it the tokens come back whole and nothing else happens) and `min_out` the least of `to` the buy
/// accepts (below it the USDm arrives in this wallet instead). Either way the person is never left with less than a
/// floor they stated. The second token arrives one batch after the first leg, as an ordinary note of this wallet.
/// BORROWED: Uniswap's routed swap through a common pair (token → base → token).
pub(crate) fn swap_blocking(from_hex: String, to_hex: String, x: u64, min_usdm: u64, min_out: u64) -> Result<serde_json::Value, String> {
    let (from, to) = (token_of(&from_hex)?, token_of(&to_hex)?);
    if from == to {
        return Err("a swap names two different tokens — nothing was sent".into());
    }
    if min_usdm == 0 || min_out == 0 {
        return Err("a swap states the least it accepts on each leg — nothing was sent".into());
    }
    // the second pool must exist on this wallet's node before anything is spent: a swap into no pool would only hand
    // the USDm back, a block later
    let second = node_json("/ion/pool", serde_json::json!({ "token": hex::encode(to) }))?;
    if second.get("ready").and_then(|v| v.as_bool()) == Some(false) {
        return Err("your node is still collecting the pools from the network, so it cannot say yet whether the token you want has one — ask again shortly; nothing was sent".into());
    }
    if second.get("found").and_then(|v| v.as_bool()) != Some(true) {
        return Err("the token you want has no pool yet, so nothing can be swapped into it — nothing was sent".into());
    }
    let mut r = order_hop_blocking(it::ION_SELL, from_hex, x, 0, 0, min_usdm, to, min_out)?;
    r["detail"] = serde_json::json!("The swap was accepted. A block pays the sale into the second pool and the next one pays you the token you asked for; it arrives in this wallet on its own.");
    Ok(r)
}

/// A swap's or any other order with no lock words: [`order_full_blocking`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn order_hop_blocking(kind: u8, token_hex: String, x: u64, y: u64, shares: u64, min_out: u64, hop: [u8; 32], hop_min_out: u64) -> Result<serde_json::Value, String> {
    order_full_blocking(kind, token_hex, x, y, shares, min_out, hop, hop_min_out, 0, 0)
}

/// ⭐ BUILD AND SEND ONE ORDER. `kind` is one of `ion_pool_tx::ION_*`; the amounts are atomic units and only this kind's
/// may be non-zero (the node refuses any other shape). `hop` is the second pool of a swap (all zero on every other
/// order) and `hop_min_out` its floor. `lock_from` and `lock_until` are the lock weeks of a removal, a lock or an
/// unlock (spec §14; zero on every other order). Nothing is spent unless the node answers that it pooled the order.
#[allow(clippy::too_many_arguments)]
pub(crate) fn order_full_blocking(
    kind: u8,
    token_hex: String,
    x: u64,
    y: u64,
    shares: u64,
    min_out: u64,
    hop: [u8; 32],
    hop_min_out: u64,
    lock_from: u32,
    lock_until: u32,
) -> Result<serde_json::Value, String> {
    let token = token_of(&token_hex)?;
    let fee = wr::PROTOCOL_FEE_ATOMIC;
    // a claim is the creator's alone: asked before anything is picked or proven
    let creator_facts = if kind == it::ION_CLAIM {
        let f = creator_facts(&token)?;
        if !f.4 {
            return Err("this wallet's key did not create that token, so its creator fees are not this wallet's — nothing was sent".into());
        }
        Some(f)
    } else {
        None
    };
    let (my_ek, loc_sk, out_sk, keys, mark) = {
        let g = locked(&WALLET);
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.scan_ek.clone(), w.loc_sk, w.out_sk, w.note_keys(), wallet_mark(&w.spend_pk))
    };
    // what this kind of order brings, in the order's own leg order
    let shape = it::IonOrderCore { kind, x, y, shares, min_out, owner_opening: [0u8; 32], shell_ct: Vec::new(), shell_pad: [0u8; 32], shell_vt: 0, locators: [[0u8; 32]; 3], hop, hop_min_out, lock_from, lock_until };
    let wants = shape.legs().ok_or("that is not an order: only the amounts its kind brings may be set — nothing was spent")?;
    // a change of this wallet's own that the chain has carried since the last look is landed first (one detection
    // pass, only when something is in flight), so an order straight after another finds its change without an
    // outside refresh
    land_in_flight_change_once();
    // one note of this wallet for each asset the order brings (the smallest that covers it)
    let picks: Vec<(it::IonAsset, u64, u64, Digest4, Vec<u8>)> = {
        let s = locked(&SCAN);
        let st = s.as_ref().ok_or("the wallet has not scanned yet")?;
        let mut used: Vec<Digest4> = Vec::new();
        let mut out = Vec::with_capacity(wants.len());
        let proven: HashSet<[u8; 32]> = PROVEN_SPENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
        // WHY NOTHING FITS, said with the refusal: an order this wallet sent a moment ago still holds its change (it
        // arrives with the block that carries the order), or the wallet's own remainder from a payment is on its way.
        // Either is "ask again shortly", never "you do not have it".
        let flight = {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let waiting = locked(&SENT).iter().any(|o| o.wallet == mark && now.saturating_sub(o.at) < ORDER_IN_FLIGHT_SECS && !st.owned.iter().any(|n| n.opening == o.opening));
            let mut why = own_change_in_flight_note(st);
            if waiting {
                why.push_str(" — an order this wallet sent a moment ago is still in flight: its change and what it pays arrive within a minute or two, so ask again shortly");
            }
            why
        };
        for (asset, amount) in &wants {
            let tag = it::ion_tag(&token, *asset);
            let need = amount.checked_add(if *asset == it::IonAsset::Usdm { fee } else { 0 }).ok_or("the amount does not fit")?;
            let n = st
                .owned
                .iter()
                // the wallet's ONE rule for "spendable now" (`spendable_now`): not spent here, not proven spent by the
                // chain, not an open order's input, and not a change no block carries yet
                .filter(|n| n.asset == tag && n.amount >= need && !used.contains(&n.seed) && spendable_now(&st.spent, &st.pending_change, &proven, n.amount, n.seed, &n.nf))
                .min_by_key(|n| n.amount)
                .ok_or_else(|| {
                    // one order spends ONE note of each asset it brings: a balance held in several notes is combined first
                    let base = match asset {
                        it::IonAsset::Usdm => "no single USDm note in this wallet covers that amount and the network fee (an order spends one note; to use more, first send the amount to your own address, which arrives as one note) — nothing was spent",
                        it::IonAsset::Token => "no single note of this token in this wallet covers that amount (an order spends one note; to use more, first send the amount to your own address, which arrives as one note) — nothing was spent",
                        it::IonAsset::Share => "no single share note of this pool covers that amount (remove one share note at a time) — nothing was spent",
                        it::IonAsset::Locked(_) => "no single note of this pool's shares locked until that date covers that amount (one locked share note at a time) — nothing was spent",
                    };
                    format!("{base}{flight}")
                })?;
            used.push(n.seed);
            out.push((*asset, *amount, n.amount, n.seed, n.note.clone()));
        }
        out
    };
    let input_nfs: Vec<[u8; 32]> = picks.iter().map(|(asset, _, value, seed, _)| pq_spend::note_nullifier_asset(*value, &keys.owner(*seed), it::ion_tag(&token, *asset))).collect();
    let changes: Vec<u64> = picks.iter().map(|(asset, amount, value, _, _)| value - amount - if *asset == it::IonAsset::Usdm { fee } else { 0 }).collect();
    // this wallet's own locators: three for the payout notes, one for each change that holds something
    let reservation = reserve_chg_indices(3 + changes.iter().filter(|c| **c > 0).count(), &input_nfs)?;
    let dom = chg_domain();
    let idx = &reservation.indices;
    if idx.len() < 3 {
        return Err("this wallet could not reserve the payout's locators — nothing was spent".into());
    }
    let (shell_ct, shell_pad, shell_vt, opening) = pq::seal_payout_shell(&my_ek, &keys.spk).ok_or("could not seal the payout notes — nothing was spent")?;
    let core = it::IonOrderCore {
        kind,
        x,
        y,
        shares,
        min_out,
        owner_opening: leaf4_to_bytes(opening),
        shell_ct: shell_ct.to_vec(),
        shell_pad,
        shell_vt,
        locators: [locator_word(&loc_sk, &dom, idx[0]), locator_word(&loc_sk, &dom, idx[1]), locator_word(&loc_sk, &dom, idx[2])],
        hop,
        hop_min_out,
        lock_from,
        lock_until,
    };
    let bind = it::ion_order_bind(&token, &core);
    let my_dk = own_scan_dk()?;
    let agent = agent();
    let mut next_change = 3usize;
    let mut legs = Vec::with_capacity(picks.len());
    for (k, ((asset, amount, value_in, seed, in_note), (input_nf, change))) in picks.iter().zip(input_nfs.iter().zip(&changes)).enumerate() {
        let tag = it::ion_tag(&token, *asset);
        let in_owner = keys.owner(*seed);
        // the change: its own locator when it holds something, a throwaway one when it is nothing
        let j_change = if *change > 0 {
            let j = idx.get(next_change).copied().ok_or("this wallet could not reserve the change's locator — nothing was spent")?;
            next_change += 1;
            Some(j)
        } else {
            None
        };
        let (change_note, change_opening) = match j_change {
            Some(j) => pq::seal_change_with_record(&my_ek, &keys.spk, in_note, &my_dk, *change, &out_sk, input_nf, &dom, j),
            None => pq::seal_note_full_asset(&my_ek, &keys.spk, 0, tag),
        }
        .ok_or("could not seal the change — nothing was spent")?;
        let lc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was spent")?;
        // FIRST the one thing that can say "not yet": the spent note's membership (a note is provable a few blocks
        // after it lands). Asked before the spend is proven, so "ask again shortly" comes back in the time of one read,
        // not after seconds of proving that would be thrown away.
        let cm_in = leaf4_to_bytes(wr::asset_note_cm(*value_in, tag, in_owner.opening()));
        let nf_in = usdmd_node::spend_frontier::cm_bytes_to_root(input_nf).ok_or("refusing: a spent note's nullifier is not a canonical digest — nothing was spent")?;
        let (mem, tip) = membership_bind_for(&agent, &cm_in, nf_in, lc_blind).ok_or(MEMBERSHIP_UNPROVABLE_YET)?;
        let burn = it::ion_burn_opening(&bind, k);
        let (carrier, cms, nf, lc) = if *asset == it::IonAsset::Usdm {
            let w = wr::SpendValidityWitness {
                value_in: *value_in,
                owner: in_owner,
                value_out: value_in - fee,
                fee,
                lc_blind,
                out0_value: *amount,
                out0_opening: burn,
                out1_value: *change,
                out1_opening: change_opening,
            };
            wr::prove_bond_validity_carrier_with_commit_bytes(&w, *amount).ok_or("the USDm spend did not prove — nothing was spent")?
        } else {
            let w = wr::AssetSpendValidityWitness {
                value_in: *value_in,
                owner: in_owner,
                value_out: *value_in,
                fee: 0,
                lc_blind,
                out0_value: *amount,
                out0_opening: burn,
                out1_value: *change,
                out1_opening: change_opening,
                asset: tag,
            };
            wr::prove_asset_bond_validity_carrier_bytes(&w, *amount).ok_or("the spend did not prove — nothing was spent")?
        };
        if leaf4_to_bytes(nf) != *input_nf || change_note[..32] != leaf4_to_bytes(cms[1])[..] {
            return Err("refusing: a spend's nullifier or change is not this order's — nothing was spent".into());
        }
        let change_cm = leaf4_to_bytes(cms[1]);
        let recs = self_note_clue_records(&loc_sk, &[change_cm], &[j_change]);
        let change_clue = recs.get(34..).filter(|c| !c.is_empty()).map(<[u8]>::to_vec).ok_or("the change's clue could not be derived — nothing was spent")?;
        legs.push(usdmd_node::asset_tx::CreationFee {
            nullifier: *input_nf,
            leaf_commit: leaf4_to_bytes(lc),
            carrier,
            membership_carrier: hex::decode(&mem).map_err(|e| format!("member leg hex: {e}"))?,
            membership_tip: hex::decode(&tip).map_err(|e| format!("member tip hex: {e}"))?,
            change_note: change_note.to_vec(),
            change_clue,
        });
    }
    // a claim carries its creator's word: this wallet's key, as the key the token's id binds, signs THIS order
    let creator = match creator_facts {
        Some((asset_kind, symbol, name, logo, _)) => {
            let (spend_pk, spend_sk) = {
                let g = locked(&WALLET);
                let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
                (w.spend_pk.clone(), w.spend_sk.clone())
            };
            let sig = usdmd_node::pqauth::ml_dsa_sign(&it::ion_claim_msg(&token, &bind), spend_sk.as_slice()).ok_or("this wallet could not sign the claim — nothing was spent")?;
            Some(it::IonCreatorAuth { kind: asset_kind, symbol, name, logo, pubkey: spend_pk, sig })
        }
        None => None,
    };
    let order = it::IonOrderTx { token, core, legs, creator };
    if it::IonOrderTx::decode(&order.encode()).as_ref() != Some(&order) || !order.legs_verify() || !order.creator_verifies(&usdmd_node::pqauth::MlDsaVerifier) {
        return Err("refusing: the order does not verify against its own spends — nothing was spent".into());
    }
    let reply: serde_json::Value = agent
        .post(&format!("{}/submit_ion_order", node_url()))
        .send_json(serde_json::json!({ "order_hex": hex::encode(order.encode()) }))
        .map_err(|e| format!("the node refused the order: {}", node_refusal(e)))
        .and_then(|r| r.into_json().map_err(|e| format!("order reply json: {e}")))?;
    if reply.get("verdict").and_then(|v| v.as_str()) != Some("PUBLISHED") {
        return Err(match reply.get("detail").and_then(|v| v.as_str()) {
            Some(why) => format!("the node did not take the order: {why}"),
            None => "the node did not take the order".to_string(),
        });
    }
    reservation.commit(input_nfs[0]);
    // the Activity page's view of what this run sent (in memory only: [`SentOrder`])
    {
        let mut sent = locked(&SENT);
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        sent.push(SentOrder { wallet: mark, id: order.id(), kind, token, hop, x, y, shares, lock_from, lock_until, opening, at });
        let extra = sent.len().saturating_sub(SENT_KEPT);
        sent.drain(..extra);
    }
    // THE ACCEPTED ORDER'S SPENDS, in this wallet's own view: each input is spent here and its CHANGE is held in its
    // place as this wallet's own money in flight (the wallet's one rule for an accepted object,
    // `hold_object_change_in_flight`: the balance never reads as if the change were gone, every selection's empty
    // answer names it, and the next spend lands it first). A leg with no change takes the bare spent mark, written to
    // the wallet's store in the same step. The chain's own answer confirms or returns them like any spend's.
    let mut bare = false;
    for (k, (_, _, value_in, seed, _)) in picks.iter().enumerate() {
        let held = changes[k] > 0 && order.legs.get(k).is_some_and(|f| hold_object_change_in_flight((*value_in, *seed), &f.change_note));
        if !held {
            let mut s = locked(&SCAN);
            if let Some(st) = s.as_mut() {
                mark_spent(st, (*value_in, *seed));
                bare = true;
            }
        }
    }
    if bare {
        persist_after_spend();
    }
    Ok(serde_json::json!({
        "accepted": true,
        "order_id": hex::encode(order.id()),
        "detail": "The order was accepted. The block after the one that carries it pays it; what you receive arrives in this wallet on its own.",
    }))
}

/// What a caller is told when a note this order spends is not final on the chain yet (it is asked again, as a person would).
const MEMBERSHIP_UNPROVABLE_YET: &str = "MEMBERSHIP_UNPROVABLE: the membership of a note this order spends cannot be proved yet (the note is not final on the chain) — ask again shortly; nothing was spent";

/// REMOVE LIQUIDITY: hand back `shares` of this wallet's PLAIN shares of a pool ([`share_orders_blocking`]); `0` hands back
/// every plain share this wallet holds.
pub(crate) fn remove_blocking(token_hex: String, shares: u64) -> Result<serde_json::Value, String> {
    share_orders_blocking(it::ION_REMOVE, token_hex, shares, 0, 0)
}

/// REMOVE LOCKED LIQUIDITY (spec §14): hand back shares locked until `week`. The chain pays them out only from that
/// Monday on (before it, the order is handed back whole, the locked shares with it), so the wallet refuses to send it
/// earlier and says the date.
pub(crate) fn remove_locked_blocking(token_hex: String, shares: u64, week: u32) -> Result<serde_json::Value, String> {
    let now = lock_now_week(&token_hex)?;
    if week == 0 || now < week {
        return Err(format!("these shares are locked until {} — they can be taken out from that day on, and earn fees until then; nothing was sent", week_date(week)));
    }
    share_orders_blocking(it::ION_REMOVE, token_hex, shares, week, 0)
}

/// LOCK LIQUIDITY (spec §14; user 2026-11-12: "the optional ability to lock their liquidity … with the ability to select
/// the amount of time/unlock date"): turn `shares` of this wallet's plain shares (`from_week == 0`), or of its shares
/// locked until `from_week` (an extension), into shares locked until `until_week`. The date must be a Monday after this
/// week and at most [`it::ION_LOCK_WEEKS_MAX`] weeks on; an extension only lengthens. The shares keep earning fees.
pub(crate) fn lock_blocking(token_hex: String, shares: u64, from_week: u32, until_week: u32) -> Result<serde_json::Value, String> {
    let now = lock_now_week(&token_hex)?;
    if until_week <= now || until_week > now.saturating_add(it::ION_LOCK_WEEKS_MAX) {
        return Err(format!(
            "a lock's unlock date is a Monday after this week and at most four years away (the latest is {}) — nothing was sent",
            week_date(now.saturating_add(it::ION_LOCK_WEEKS_MAX))
        ));
    }
    if until_week <= from_week {
        return Err(format!("a lock can only be made longer: these shares are already locked until {} — nothing was sent", week_date(from_week)));
    }
    share_orders_blocking(it::ION_LOCK, token_hex, shares, from_week, until_week)
}

/// UNLOCK (spec §14): from the unlock date on, turn shares locked until `week` back into plain shares (a provider who
/// stays in the pool; to leave it, remove them directly).
pub(crate) fn unlock_blocking(token_hex: String, shares: u64, week: u32) -> Result<serde_json::Value, String> {
    let now = lock_now_week(&token_hex)?;
    if week == 0 || now < week {
        return Err(format!("these shares are locked until {} — nothing was sent", week_date(week)));
    }
    share_orders_blocking(it::ION_UNLOCK, token_hex, shares, week, 0)
}

/// The lock week of this wallet's node's chain clock, as its pool route reads it (what the chain will judge a lock
/// order against is the settling block's own clock, a block or two later; a date right at the edge is the chain's call,
/// and an order it does not take is handed back whole).
fn lock_now_week(token_hex: &str) -> Result<u32, String> {
    let token = token_of(token_hex)?;
    let r = node_json("/ion/pool", serde_json::json!({ "token": hex::encode(token) }))?;
    if r.get("found").and_then(|v| v.as_bool()) != Some(true) {
        return Err("that token has no pool on this wallet's node yet — nothing was sent".into());
    }
    r.pointer("/pool/lock/now_week").and_then(serde_json::Value::as_u64).and_then(|w| u32::try_from(w).ok()).ok_or_else(|| "this wallet's node did not say the chain's week — nothing was sent".into())
}

/// A lock week as the date a person reads, for an approval sheet: [`week_date`].
pub(crate) fn week_words(week: u32) -> String {
    week_date(week)
}

/// A lock week as the date a person reads: the Monday it begins on (UTC).
fn week_date(week: u32) -> String {
    let days = i64::try_from(it::lock_week_start_secs(week) / 86_400).unwrap_or(0);
    // civil-from-days (Howard Hinnant's algorithm): the proleptic Gregorian date of a day count since 1970-01-01
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    format!("Monday {d} {} {y}", MONTHS[usize::try_from(m - 1).unwrap_or(0)])
}

/// ⭐ ONE ORDER KIND OVER THIS WALLET'S SHARE NOTES of one share asset (plain when `lock_from == 0`, else locked until
/// it): a removal, a lock or an unlock of `shares` (`0`: every share of that asset this wallet holds). One share note
/// covers one order, so an amount that spans several notes is sent as several orders, the largest note first.
fn share_orders_blocking(kind: u8, token_hex: String, shares: u64, lock_from: u32, lock_until: u32) -> Result<serde_json::Value, String> {
    let token = token_of(&token_hex)?;
    let share_tag = it::ion_tag(&token, if lock_from == 0 { it::IonAsset::Share } else { it::IonAsset::Locked(lock_from) });
    let mut notes: Vec<u64> = {
        let s = locked(&SCAN);
        let st = s.as_ref().ok_or("the wallet has not scanned yet")?;
        st.owned.iter().filter(|n| n.asset == share_tag && n.amount > 0 && !st.spent.contains(&(n.amount, n.seed))).map(|n| n.amount).collect()
    };
    notes.sort_unstable_by(|a, b| b.cmp(a));
    let held: u128 = notes.iter().map(|n| u128::from(*n)).sum();
    if held == 0 {
        return Err(if lock_from == 0 {
            "this wallet holds no part of that pool — nothing was sent".to_string()
        } else {
            format!("this wallet holds no shares of that pool locked until {} — nothing was sent", week_date(lock_from))
        });
    }
    let mut left: u128 = if shares == 0 { held } else { u128::from(shares) };
    if left > held {
        return Err("this wallet holds fewer of those shares than that — nothing was sent".into());
    }
    let mut ids = Vec::new();
    // Each order pays the network fee from a USDm note of this wallet, and a wallet with ONE USDm note has none to
    // spend again until the first order's change arrives (a block or two). So an order over several share notes can
    // be accepted in part: what was sent is said, what was not is said, and nothing is reported as done that is not.
    let mut stopped: Option<String> = None;
    for n in notes {
        if left == 0 {
            break;
        }
        let take = u64::try_from(left.min(u128::from(n))).map_err(|_| "the amount does not fit")?;
        match order_full_blocking(kind, token_hex.clone(), 0, 0, take, 0, [0u8; 32], 0, lock_from, lock_until) {
            Ok(r) => {
                ids.push(r.get("order_id").cloned().unwrap_or(serde_json::Value::Null));
                left -= u128::from(take);
            }
            Err(why) if ids.is_empty() => return Err(why),
            Err(why) => {
                stopped = Some(why);
                break;
            }
        }
    }
    let what = match kind {
        it::ION_LOCK => format!("Your lock was accepted. The shares come back to this wallet locked until {} and keep earning fees until then.", week_date(lock_until)),
        it::ION_UNLOCK => "Your unlock was accepted. The shares come back to this wallet as ordinary shares you can take out at any time.".to_string(),
        _ => "Your removal was accepted. Both assets arrive in this wallet on their own, usually within a minute.".to_string(),
    };
    let detail = match &stopped {
        None => what,
        Some(why) => format!(
            "Part of it was accepted ({} of your share notes) and is on its way to this wallet. The rest was NOT sent and is still in the pool, yours as before: {why} Send the rest once this part has arrived.",
            ids.len()
        ),
    };
    Ok(serde_json::json!({ "accepted": true, "complete": stopped.is_none(), "left_shares": left.to_string(), "orders": ids, "detail": detail }))
}

#[cfg(test)]
mod week_date_tests {
    /// A lock week reads as the Monday it begins on, the chain's own grid (`ion_pool_tx::lock_week_start_secs`): week 0 is
    /// Monday 5 January 1970, and the date is checked against two known Mondays.
    /// TWO-PARTY-REVIEWED: a pure date rendering of one public number; no second party.
    #[test]
    fn a_lock_week_reads_as_its_monday() {
        assert_eq!(super::week_date(0), "Monday 5 January 1970");
        // Monday 16 November 2026 = 1,794,787,200 s; its week is (that − 345,600) / 604,800
        let w = u32::try_from((1_794_787_200u64 - 345_600) / 604_800).expect("fits");
        assert_eq!(super::week_date(w), "Monday 16 November 2026");
        assert_eq!(super::week_date(w + 1), "Monday 23 November 2026");
    }
}

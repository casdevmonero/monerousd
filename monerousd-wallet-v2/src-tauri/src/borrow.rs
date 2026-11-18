// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-4 — BORROW USDm AGAINST BITCOIN (R7 F8, ADOPTABLE A4): the wallet's half of the debt units
//! (docs/BR-4-7-PRIVATE-POSITIONS-SPEC-20261029.md §10.3–§10.4).
//!
//! - **Options** (`wallet_borrow_options`): every unit size at every band from the one just under the chain's price down six
//!   bands, each with its collateral in BTC and dollars, the price at which it is liquidated and how far away that is.
//! - **Open** (`wallet_borrow_open`): a deposit address exactly like "Add money", whose mint request carries the unit's half
//!   (its note, sealed to this wallet under the unit's tag, the note's carrier and clue). Custody mints `U` USDm and the unit
//!   note once the Bitcoin confirms; the half is rebuilt if the day or the band's epoch moved before the deposit confirmed.
//! - **Positions** (`wallet_borrow_positions`): each open unit with its debt today and its distance to liquidation.
//! - **Close** (`wallet_borrow_close`): burns the unit note and the debt (`U` plus interest) under one Bitcoin ticket; custody
//!   returns the collateral in payout-ladder pieces to the address the user names.
//!
//! BORROWED: Liquity's open/closeTrove on the chain's own peg-in, burn and payout doors.
//! DIGITAL-CASH-PRIVACY-REVIEWED: a unit's band, size and day are public by design (§10.3); the owner, the change and the
//! Bitcoin destination stay hidden; nothing here is sent to anyone but this wallet's own node.

use super::*;
use usdm_decider::whir_rec_block as wr;
use usdmd_node::debt_units as du;

/// The unit a borrow opens, kept with its deposit's swap record on this device only.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct UnitSwap {
    pub k: u8,
    pub l: u8,
    /// The unit half the mint request carries (postcard of `unit_open_tx::UnitPart`).
    pub part: Vec<u8>,
    /// The unit note's opening (what its carrier binds).
    pub opening: Digest4,
    /// Set once the close is relayed: the unit note's nullifier (the close's handle).
    #[serde(default)]
    pub close_nf: Option<[u8; 32]>,
}

/// A lock this module reads through: a poisoned lock still holds the same data (a panicking holder elsewhere does not change a
/// key or a scan), so it is read as it stands.
fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The public unit book this wallet's node answers.
fn unit_book() -> Result<serde_json::Value, String> {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build()
        .post(&format!("{}/unit_book", node_url()))
        .send_json(serde_json::json!({}))
        .map_err(|e| format!("unit book: {}", node_refusal(e)))?
        .into_json()
        .map_err(|e| format!("unit book json: {e}"))
}

/// The chain's reference price word for Bitcoin (USDm atomic per sat × scale) and the scale, from the unit book.
fn book_price(b: &serde_json::Value) -> Result<(u128, u128), String> {
    let price = b["reference_price"].as_str().and_then(|p| p.parse::<u128>().ok()).filter(|p| *p > 0).ok_or("the chain has not priced Bitcoin yet — borrowing opens when it does")?;
    let scale = b["scale"].as_u64().map(u128::from).filter(|s| *s > 0).ok_or("the unit book names no price scale")?;
    Ok((price, scale))
}

fn band_epoch(b: &serde_json::Value, k: usize) -> Result<u64, String> {
    b["band_epochs"].get(k).and_then(serde_json::Value::as_u64).ok_or_else(|| "the unit book names no epoch for this band".to_string())
}

fn book_day(b: &serde_json::Value) -> Result<u64, String> {
    b["day"].as_u64().ok_or_else(|| "the unit book names no day".to_string())
}

/// The debt a unit owes on `today`: `U × I(today) / I(open day)`, rounded up (the fold's exact rule, `UnitBook::close_terms`).
fn debt_on(t: &du::UnitTerms, today: u64) -> Result<u64, String> {
    let u = t.unit_atomic().ok_or("no such unit size")?;
    let d = (u * du::interest_index(today)).checked_div(du::interest_index(t.day)).ok_or("the interest index is zero")?;
    let exact = d * du::interest_index(t.day) == u * du::interest_index(today);
    u64::try_from(if exact { d } else { d + 1 }).map_err(|_| "the debt does not fit".to_string())
}

/// ⭐ THE OPTIONS — every size at the seven bands at and under the chain's price, each priced in dollars before anything moves.
pub(crate) fn borrow_options_blocking() -> Result<serde_json::Value, String> {
    let b = unit_book()?;
    let (price, scale) = book_price(&b)?;
    let usd = price as f64 / scale as f64; // a price word is USDm atomic per sat × scale: dollars per Bitcoin
    let top = du::band_of_price(price).ok_or("Bitcoin is priced under the lowest band — no unit can open")?;
    let lowest = top.saturating_sub(6);
    let mut options = Vec::new();
    for l in 0..du::UNIT_ATOMIC.len() {
        for k in (lowest..=top).rev() {
            let sats = du::collateral_sats(l, k);
            let floor = du::band_price_word(k) as f64 / scale as f64;
            let usdm = du::UNIT_ATOMIC[l] as f64 / 1e8;
            options.push(serde_json::json!({
                "l": l, "k": k, "usdm": usdm,
                "collateral_btc": sats as f64 / 1e8,
                "collateral_usd": sats as f64 / 1e8 * usd,
                "deposit_btc": (sats as u64).saturating_add(SWEEP_FEE_SATS) as f64 / 1e8,
                "liquidation_usd": floor,
                "drop_pct": (1.0 - floor / usd) * 100.0,
                "ratio_pct": sats as f64 / 1e8 * usd / usdm * 100.0,
            }));
        }
    }
    // the default: 1,000 USDm at the first band that leaves Bitcoin at least 30 % of room to fall (the lowest offered if none)
    let safe = conservative_band(lowest, top, usd, scale);
    Ok(serde_json::json!({
        "usd_per_btc": usd,
        "day": book_day(&b)?,
        "rate_apr_pct": du::UNIT_RATE_BPS as f64 / 100.0,
        "cash_in_fee_pct": 0.10,
        "sweep_fee_btc": SWEEP_FEE_SATS as f64 / 1e8,
        "default": { "l": 2, "k": safe },
        "options": options,
    }))
}

/// Seal a fresh unit half for `(l, k)` at the book's day and band epoch, bound to the deposit at `reserve_address`.
fn fresh_unit_half(b: &serde_json::Value, l: u8, k: u8, reserve_address: &str) -> Result<(UnitSwap, usdmd_node::unit_open_tx::UnitPart), String> {
    let terms = du::UnitTerms { k, l, day: book_day(b)?, epoch: band_epoch(b, usize::from(k))? };
    let u = u64::try_from(terms.unit_atomic().ok_or("no such unit size or band")?).map_err(|_| "the unit does not fit")?;
    let (scan_ek, spk, loc_sk) = {
        let g = locked(&WALLET);
        let w = g.as_ref().ok_or("wallet locked")?;
        (w.scan_ek.clone(), w.note_spk, w.loc_sk)
    };
    let (note, opening) = pq::seal_note_full_asset(&scan_ek, &spk, u, terms.tag()).ok_or("could not seal the unit note — nothing was requested")?;
    let (carrier, cm) = wr::prove_asset_mint_validity_bytes(u, terms.tag(), &opening).ok_or("the unit note's carrier did not prove — nothing was requested")?;
    if leaf4_to_bytes(cm)[..] != note[..32] {
        return Err("refusing: the unit note is not its carrier's — nothing was requested".into());
    }
    let (clue, reservation) = fresh_self_note_clue(&loc_sk, &note)?;
    let base = usdmd_node::peg::deposit_id_for_reserve_address(reserve_address);
    let claim = usdmd_node::unit_open_tx::UnitClaim { base_deposit_id: base, terms, unit_cm: leaf4_to_bytes(cm) };
    let part = usdmd_node::unit_open_tx::UnitPart { claim, unit_note: note.to_vec(), unit_clue: clue, unit_carrier: carrier };
    if !part.verifies() {
        return Err("refusing: the unit half does not verify against itself — nothing was requested".into());
    }
    reservation.commit(claim.deposit_id());
    let bytes = postcard::to_allocvec(&part).map_err(|e| format!("the unit half does not encode: {e}"))?;
    Ok((UnitSwap { k, l, part: bytes, opening, close_nf: None }, part))
}

/// ⭐ OPEN — a deposit address whose mint opens one unit of size `l` at band `k`.
pub(crate) fn borrow_open_blocking(l: u8, k: u8) -> Result<serde_json::Value, String> {
    let b = unit_book()?;
    let (price, scale) = book_price(&b)?;
    let top = du::band_of_price(price).ok_or("Bitcoin is priced under the lowest band — no unit can open")?;
    if usize::from(k) > top {
        return Err("this band's floor is above Bitcoin's price: the unit would be liquidated at once — pick a lower band".into());
    }
    let u = du::UNIT_ATOMIC.get(usize::from(l)).copied().ok_or("no such unit size")?;
    let swap = buy_swap_inner("BTC".to_string(), u as f64 / 1e8, false)?;
    let swap_id = swap["swap_id"].as_str().ok_or("the deposit record has no id")?.to_string();
    let reserve_address = swap["deposit_address"]
        .as_str()
        .filter(|a| !a.is_empty())
        .ok_or("the reserve has no deposit address yet (the custody quorum is still forming) — nothing was requested")?
        .to_string();
    let (unit, _part) = fresh_unit_half(&b, l, k, &reserve_address)?;
    let mut list = read_swaps();
    let idx = list.iter().position(|s| s.swap_id == swap_id).ok_or("the deposit record vanished")?;
    list[idx].unit = Some(unit);
    write_swaps(&list);
    let sats = du::collateral_sats(usize::from(l), usize::from(k));
    Ok(serde_json::json!({
        "swap_id": swap_id,
        "deposit_address": reserve_address,
        "deposit_btc": (sats as u64).saturating_add(SWEEP_FEE_SATS) as f64 / 1e8,
        "usdm": u as f64 / 1e8,
        "liquidation_usd": du::band_price_word(usize::from(k)) as f64 / scale as f64,
    }))
}

/// The unit half a mint poll must carry for swap `idx`: the stored one while the day and the band's epoch still match the
/// chain, else a fresh one (a unit is dated exactly at the fold; the deposit and its address are unchanged).
pub(crate) fn current_unit_half(list: &mut [SwapRec], idx: usize) -> Result<Option<usdmd_node::unit_open_tx::UnitPart>, String> {
    let Some(unit) = list[idx].unit.clone() else { return Ok(None) };
    let part: usdmd_node::unit_open_tx::UnitPart = postcard::from_bytes(&unit.part).map_err(|e| format!("the stored unit half does not decode: {e}"))?;
    let b = unit_book()?;
    if part.claim.terms.day == book_day(&b)? && part.claim.terms.epoch == band_epoch(&b, usize::from(unit.k))? {
        return Ok(Some(part));
    }
    let reserve_address = list[idx].deposit_address.clone();
    let (fresh, part) = fresh_unit_half(&b, unit.l, unit.k, &reserve_address)?;
    list[idx].unit = Some(fresh);
    list[idx].mint_note = None; // the mint request names the unit's deposit id: a fresh poll seals its note again
    list[idx].mint_clue = None;
    write_swaps(list);
    Ok(Some(part))
}

/// ⭐ POSITIONS — each unit this wallet opened: its debt today, its collateral, the price at which it is liquidated and how
/// far Bitcoin is from it (A4: a warning under 15 %).
pub(crate) fn borrow_positions_blocking() -> Result<serde_json::Value, String> {
    let b = unit_book()?;
    let (price, scale) = book_price(&b)?;
    let usd = price as f64 / scale as f64;
    let today = book_day(&b)?;
    let mut out = Vec::new();
    for s in read_swaps() {
        let Some(unit) = s.unit.as_ref() else { continue };
        let Ok(part) = postcard::from_bytes::<usdmd_node::unit_open_tx::UnitPart>(&unit.part) else { continue };
        let t = part.claim.terms;
        let Some(ua) = t.unit_atomic() else { continue };
        let liquidated = s.status == "minted" && band_epoch(&b, usize::from(t.k))? > t.epoch;
        let floor = du::band_price_word(usize::from(t.k)) as f64 / scale as f64;
        let drop = (1.0 - floor / usd) * 100.0;
        let status = if unit.close_nf.is_some() {
            "closing"
        } else if liquidated {
            "liquidated"
        } else {
            s.status.as_str()
        };
        out.push(serde_json::json!({
            "swap_id": s.swap_id,
            "status": status,
            "usdm": ua as f64 / 1e8,
            "debt_usdm": debt_on(&t, today)? as f64 / 1e8,
            "collateral_btc": du::collateral_sats(usize::from(t.l), usize::from(t.k)) as f64 / 1e8,
            "liquidation_usd": floor,
            "drop_pct": drop,
            "warning": !liquidated && drop < 15.0,
            "deposit_address": s.deposit_address,
        }));
    }
    Ok(serde_json::json!({ "usd_per_btc": usd, "positions": out }))
}

/// ⭐ CLOSE — burn the unit note and its debt under one Bitcoin ticket to `payout_to`; custody returns the collateral.
pub(crate) fn borrow_close_blocking(swap_id: String, payout_to: String) -> Result<serde_json::Value, String> {
    let payout_to = payout_to.trim().to_string();
    if payout_to.is_empty() {
        return Err("enter the Bitcoin address your collateral returns to".into());
    }
    let mut list = read_swaps();
    let idx = list.iter().position(|s| s.swap_id == swap_id).ok_or("no such borrow")?;
    let unit = list[idx].unit.clone().ok_or("this deposit opened no unit")?;
    if unit.close_nf.is_some() {
        return Err("this unit's close is already on its way".into());
    }
    let part: usdmd_node::unit_open_tx::UnitPart = postcard::from_bytes(&unit.part).map_err(|e| format!("the stored unit half does not decode: {e}"))?;
    let terms = part.claim.terms;
    let u = u64::try_from(terms.unit_atomic().ok_or("no such unit")?).map_err(|_| "the unit does not fit")?;
    let b = unit_book()?;
    let today = book_day(&b)?;
    if band_epoch(&b, usize::from(terms.k))? > terms.epoch {
        return Err("this unit's band was liquidated: its Bitcoin repaid the debt and there is nothing to close (you keep the USDm)".into());
    }
    let debt = debt_on(&terms, today)?;
    let collateral = u64::try_from(du::collateral_sats(usize::from(terms.l), usize::from(terms.k))).map_err(|_| "the collateral does not fit")?;
    let fee = wr::PROTOCOL_FEE_ATOMIC;
    let (my_ek, loc_sk, out_sk, keys) = {
        let g = locked(&WALLET);
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.scan_ek.clone(), w.loc_sk, w.out_sk, w.note_keys())
    };
    // the unit note this wallet holds, and a USDm note that covers the debt and the network fee
    let (unit_seed, debt_in) = {
        let s = locked(&SCAN);
        let st = s.as_ref().ok_or("the wallet has not scanned yet")?;
        let unit_seed = st
            .owned
            .iter()
            .find(|n| n.note.len() >= 32 && n.note[..32] == part.claim.unit_cm[..])
            .map(|n| n.seed)
            .ok_or("this wallet does not hold the unit's note yet (it arrives when the deposit mints)")?;
        let debt_in = st
            .owned
            .iter()
            .filter(|n| n.asset == [0, 0, 0] && n.amount >= debt + fee)
            .min_by_key(|n| n.amount)
            .map(|n| (n.amount, n.seed, n.note.clone()))
            .ok_or("no single USDm note covers the debt and the network fee — nothing was spent")?;
        (unit_seed, debt_in)
    };
    let unit_owner = keys.owner(unit_seed);
    let unit_nf = pq_spend::note_nullifier_asset(u, &unit_owner, terms.tag());
    // the ticket over the unit note's nullifier (the node seals one share per custodian)
    let (rc, parts_hex, _leg_blind) = cashout_ticket_for(&unit_nf, &payout_to, 0, collateral, b"unit-close")?;
    let ticket: usdmd_node::peg_out_tx::TicketParts =
        postcard::from_bytes(&hex::decode(&parts_hex).map_err(|e| format!("ticket hex: {e}"))?).map_err(|e| format!("the node's ticket does not decode: {e}"))?;
    // 1) the unit note dies: U of its tag into the output bound to this close, zero change
    let opening = usdmd_node::unit_close_tx::unit_burn_opening(&terms, &rc);
    let ulc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was spent")?;
    let aw = wr::AssetSpendValidityWitness {
        value_in: u,
        owner: unit_owner,
        value_out: u,
        fee: 0,
        lc_blind: ulc_blind,
        out0_value: u,
        out0_opening: opening,
        out1_value: 0,
        out1_opening: opening,
        asset: terms.tag(),
    };
    let (unit_burn_carrier, _ucms, unf, ulc) = wr::prove_asset_bond_validity_carrier_bytes(&aw, u).ok_or("the unit burn did not prove — nothing was spent")?;
    if leaf4_to_bytes(unf) != unit_nf {
        return Err("refusing: the unit burn's nullifier is not the ticket's — nothing was spent".into());
    }
    let unit_cm_in = leaf4_to_bytes(wr::asset_note_cm(u, terms.tag(), unit_owner.opening()));
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let (umem, utip) = membership_bind_for(&agent, &unit_cm_in, unf, ulc_blind).ok_or("the unit note's membership cannot be proved yet — nothing was spent")?;
    // 2) the debt burn: `debt` USDm into the output bound to this close and the unit's nullifier, change back to this wallet
    let (value_in, in_seed, in_note) = debt_in;
    let in_owner = keys.owner(in_seed);
    let input_nf = pq_spend::note_nullifier_asset(value_in, &in_owner, [0, 0, 0]);
    let change = value_in - fee - debt;
    let reservation = reserve_chg_indices(usize::from(change > 0), &[input_nf])?;
    let dom = chg_domain();
    let my_dk = own_scan_dk()?;
    let j_change = reservation.indices.first().copied();
    let (change_note, change_opening) = match j_change {
        Some(j) => pq::seal_change_with_record(&my_ek, &keys.spk, &in_note, &my_dk, change, &out_sk, &input_nf, &dom, j),
        None => pq::seal_note_full_asset(&my_ek, &keys.spk, 0, [0, 0, 0]),
    }
    .ok_or("could not seal the change — nothing was spent")?;
    let dlc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was spent")?;
    let w = wr::SpendValidityWitness {
        value_in,
        owner: in_owner,
        value_out: value_in - fee,
        fee,
        lc_blind: dlc_blind,
        out0_value: debt,
        out0_opening: usdmd_node::unit_close_tx::debt_burn_opening(&terms, &rc, &unit_nf),
        out1_value: change,
        out1_opening: change_opening,
    };
    let (debt_burn_carrier, cms, dnf, dlc) = wr::prove_bond_validity_carrier_with_commit_bytes(&w, debt).ok_or("the debt burn did not prove — nothing was spent")?;
    if leaf4_to_bytes(dnf) != input_nf || change_note[..32] != leaf4_to_bytes(cms[1])[..] {
        return Err("refusing: the debt burn's nullifier or change is not this close's — nothing was spent".into());
    }
    let cm_in = leaf4_to_bytes(wr::asset_note_cm(value_in, [0, 0, 0], in_owner.opening()));
    let (dmem, dtip) = membership_bind_for(&agent, &cm_in, dnf, dlc_blind).ok_or("the USDm note's membership cannot be proved yet — nothing was spent")?;
    let change_cm = leaf4_to_bytes(cms[1]);
    let recs = self_note_clue_records(&loc_sk, &[change_cm], &[j_change]);
    let change_clue = recs.get(34..).filter(|c| !c.is_empty()).map(<[u8]>::to_vec).ok_or("the change's clue could not be derived — nothing was spent")?;
    let z = [0; usdm_decider::poseidon2_compress::DIGEST_LANES];
    let req = usdmd_node::unit_close_tx::UnitCloseTx {
        terms,
        unit_nullifier: unit_nf,
        unit_leaf_commit: leaf4_to_bytes(ulc),
        unit_burn_carrier,
        unit_membership_carrier: hex::decode(&umem).map_err(|e| format!("member leg hex: {e}"))?,
        unit_membership_tip: hex::decode(&utip).map_err(|e| format!("member tip hex: {e}"))?,
        debt_atomic: debt,
        debt_nullifier: input_nf,
        debt_leaf_commit: leaf4_to_bytes(dlc),
        debt_burn_carrier,
        debt_membership_carrier: hex::decode(&dmem).map_err(|e| format!("member leg hex: {e}"))?,
        debt_membership_tip: hex::decode(&dtip).map_err(|e| format!("member tip hex: {e}"))?,
        change_note: change_note.to_vec(),
        change_clue,
        ticket,
        redeem_commit: rc,
        new_minted_commit: z,
        new_reserve_commit: z,
        retire_leg: Vec::new(),
        release_leg: Vec::new(),
        attestors: Vec::new(),
    };
    if !req.carriers_verify() {
        return Err("refusing: the close does not verify against its own burns — nothing was spent".into());
    }
    let reply: serde_json::Value = agent
        .post(&format!("{}/unit_close", node_url()))
        .send_json(serde_json::json!({ "request_hex": hex::encode(req.encode().ok_or("the close does not encode")?) }))
        .map_err(|e| format!("the node refused the close: {}", node_refusal(e)))
        .and_then(|r| r.into_json().map_err(|e| format!("close reply json: {e}")))?;
    if reply.get("relayed").and_then(|v| v.as_bool()) != Some(true) {
        return Err(match reply.get("reason").and_then(|v| v.as_str()) {
            Some(why) => format!("the node did not relay the close: {why}"),
            None => "the node did not relay the close".to_string(),
        });
    }
    reservation.commit(input_nf);
    list[idx].unit = Some(UnitSwap { close_nf: Some(unit_nf), ..unit });
    write_swaps(&list);
    Ok(serde_json::json!({
        "relayed": true,
        "debt_usdm": debt as f64 / 1e8,
        "interest_usdm": (debt - u) as f64 / 1e8,
        "collateral_btc": collateral as f64 / 1e8,
    }))
}

/// The default band: the highest of `lowest..=top` whose floor leaves Bitcoin at least 30 % of room to fall from `usd` (the
/// lowest offered if none does) — a protection on by default (ADOPTABLE A4), pinned in `a4_protection_tests`.
pub(crate) fn conservative_band(lowest: usize, top: usize, usd: f64, scale: u128) -> usize {
    match (lowest..=top).rev().find(|k| du::band_price_word(*k) as f64 / scale as f64 <= usd * 0.7) {
        Some(k) => k,
        None => lowest,
    }
}

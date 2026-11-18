// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-15 + §18.14 — TRADING SAT: the wallet's half of the private DeFi layer, SAT against Bitcoin and against Monero.
//!
//! - **Book** (`wallet_defi_book`): whether the pool is open and taking orders, the last clearing price in the coin, and what an
//!   amount trades for at it — what the confirmation shows before anything is spent.
//! - **Chart** (`wallet_defi_prices`): the pair's price history the chain holds (§18.15).
//! - **Buy with coin held** (`wallet_buy_sat`): ONE sealed order spending a coin note of exactly its amount, the amount and the
//!   side dealt as Shamir shares to the custody roster, each share sealed to its custodian's ML-KEM key under the custody's
//!   released key of the previous epoch (`defi_custody::order_parts`).
//! - **Buy with a deposit** (`wallet_buy_sat_deposit`): a deposit that mints a coin note atom for atom, no backing ratio and no
//!   price read; the order is placed on its own the moment it mints.
//! - **Sell** (`wallet_sell_sat`): the same sealed order spending SAT; once its coin is claimed the payout burns it rung by rung
//!   and custody pays the seller's address on the coin's own chain. A batch whose pool cannot pay returns the SAT.
//! - **Progress** (`wallet_defi_progress`): each order's batch outcome, then the CLAIM: the owner proves its fill against the
//!   claim leaf the settlement put in the note set, and mints its note to itself. The claim names no order, no batch and no tick.
//!
//! The order's secret (the amount's blind, which is also its claim nullifier's preimage) is DERIVED from this wallet's
//! outgoing-record secret and the order's index — re-derivable from the 24 words with the order list; a copy of the list
//! alone claims nothing.
//!
//! cons: none — the order list is a DEVICE-LOCAL file (never node state) that holds only the orders in flight: one ≈ 160-byte
//! row per order placed and not yet claimed, dropped the moment its claim is admitted (its SAT is then an owned note like any
//! other). Its size is f(orders in flight) — a few rows — never f(the wallet's history): no growth term.
//! LOCAL-STORAGE-REQUIRED: an order's index, amount and batch live nowhere else — the chain holds the order only as a
//! commitment (that IS its privacy), and its owner needs the three to prove its claim; it is this wallet's own record of its
//! own action, as the cash-out plan list is.
//! bound: one ≈ 160-byte row per order in flight, dropped at its claim — a few hundred bytes, never a term in height, blocks
//! or notes.
//!
//! ROOT-LAYER: the wallet is where an order and its claim are PRODUCED — it alone holds the burned note, the order's secret
//! and the fill; the node relays, and every node decides each object at the fold. An absent order list reads as empty
//! (`read_defi`): every secret is re-derivable from the words, so nothing is lost by it.
//! MEASURED: the objects built here are the ones the two-node pin measured (`br15_an_order_settles_by_audit_and_its_claim_pays_
//! exactly_its_fill_on_both_nodes`: an order of 500 → tick 693 → 249 SAT claimed on both nodes; an expired order of 400
//! refunded on both); the wallet pins `br15_buy_sat_*` measure the order secret and the quote.
//! MUST-STAY-GREEN: the repayment-pot buy and every send (the shared note selection, change reservation and member leg).
//!
//! BORROWED: Penumbra's swap + SwapClaim (a sealed batch order claimed by its owner at the batch price); this wallet's own
//! repayment-pot buy (one covering note, change back under a reserved index) for the burn.
//! DIGITAL-CASH-PRIVACY-REVIEWED: the order's amount is a commitment and its shares are sealed; the claim names nothing that
//! links it to the order; every request goes to this wallet's own node only.

use super::*;
use usdm_decider::br15_audit as ba;
use usdm_decider::whir_rec_block as wr;
use usdmd_node::defi_batch as db;

/// One order this wallet placed and has not yet claimed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct DefiOrder {
    /// ⭐ §18.14 — the pool: 0 SAT/BTC, 1 SAT/XMR
    #[serde(default)]
    pub pair: u8,
    /// ⭐ §18.14 — true: it spends SAT for the pool's coin; false: it spends the coin for SAT
    #[serde(default)]
    pub sell: bool,
    /// a sell's address on the coin's own chain, where the coin goes once it is claimed
    #[serde(default)]
    pub payout: Option<String>,
    /// the order's index (its secret is derived from it)
    pub nonce: u64,
    pub batch: u64,
    /// the note this order spends, by nullifier: what lets it be sent again
    #[serde(default)]
    pub input_nf: Option<String>,
    /// the book's batch when this order was last handed to custody
    #[serde(default)]
    pub sent_batch: u64,
    /// the note spent, atomic: SAT for a sell, the coin for a buy
    pub amount: u64,
    pub created_ms: u64,
    /// open | filled | refunded | above_max | returned
    pub status: String,
    /// the batch's tick once known (None for a refund)
    #[serde(default)]
    pub tick: Option<i64>,
    /// the lowest bucket that filled at that tick (what the claim leaf names)
    #[serde(default)]
    pub j_min: u64,
    /// whether the batch's sells counted (what the claim leaf's sellers' price names)
    #[serde(default)]
    pub sells: bool,
    /// what the claim pays, atomic
    #[serde(default)]
    pub out: u64,
    /// the claim handed to custody (its bytes, its minted note's commitment, when) — resent until its note is owned
    #[serde(default)]
    pub claim_hex: Option<String>,
    #[serde(default)]
    pub claim_cm: Option<String>,
    #[serde(default)]
    pub claim_sent_ms: u64,
    /// the book's batch when this claim was built, and the commitments of the claims it superseded (any of them may still
    /// land: the note is owned whichever one did — every copy spends the one claim nullifier, so at most one mints)
    #[serde(default)]
    pub claim_batch: u64,
    #[serde(default)]
    pub claim_prev: Vec<String>,
    /// ⭐ the order's maximum-price bucket (spec §18.10: +2 %, +10 %, +50 % over the batch's opening price, or none)
    #[serde(default = "default_bucket")]
    pub bucket: usize,
    /// ⭐ EARN — what the order is: "" a trade, "deposit" a SAT deposit into the pair's pool, "withdraw" a withdrawal of a
    /// position's units
    #[serde(default)]
    pub kind: String,
    /// a withdrawal's position (what it spends)
    #[serde(default)]
    pub position: Option<PositionRec>,
    /// the outcome's lanes: an Earn leaf, and the deposit batch's lane (the batch counted deposits and its sells cleared)
    #[serde(default)]
    pub earn: bool,
    #[serde(default)]
    pub dep: bool,
    /// ⭐ EARN STEP 3 — the income index the order's batch OPENED at (the book's `batch_index` when it was dealt): the order
    /// carries it, a deposit's limit commitment names it as its entry, a withdrawal's as its "now"
    #[serde(default)]
    pub index: u64,
    /// a withdrawal's second claim (its coin leg) — handed to custody like the first, resent until its note is owned
    #[serde(default)]
    pub claim2_hex: Option<String>,
    #[serde(default)]
    pub claim2_cm: Option<String>,
}

/// ⭐ EARN — A POSITION this wallet holds in a pair's pool: the order that made it (a SAT deposit that counted, or a
/// withdrawal whose batch paid nothing), and the leaf its batch inserted for it. Re-derivable from the words and the chain,
/// like every order secret; nothing about it is public.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PositionRec {
    pub pair: u8,
    /// the making order's amount: a deposit's SAT, or a carried withdrawal's units
    pub x: u64,
    /// the making order's nonce (its blind is derived from it)
    pub nonce: u64,
    pub bucket: u64,
    pub from_withdrawal: bool,
    /// the index its units entered at: a deposit's batch's opening index, or a carried withdrawal's own entry
    pub entry: u64,
    pub tick: i64,
    pub j_min: u64,
    pub sells: bool,
    /// ⭐ EARN STEP 3 — a carried withdrawal's "now" (its batch's opening index, beside the entry in its limit commitment)
    #[serde(default)]
    pub now: u64,
    /// ⭐ EARN STEP 3 — its leaf's deposit-batch lane
    #[serde(default)]
    pub dep: bool,
    /// "open" | "withdrawing" | "withdrawn"
    pub status: String,
    pub created_ms: u64,
}

fn default_bucket() -> usize {
    usdmd_node::defi_clear::DEFAULT_BUCKET
}

/// A buy waiting on a coin deposit: the order is placed once the swap's coin note mints.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SatIntent {
    pub swap_id: String,
    pub pair: u8,
    /// the coin the deposit mints, atomic
    pub amount: u64,
    #[serde(default = "default_bucket")]
    pub bucket: usize,
    pub created_ms: u64,
    /// waiting | failed:<why>
    pub status: String,
}

/// ⭐ §18.14 — a sell's coin on its way out: one rung of the coin's ladder at a time, from the claimed coin note, each burn naming the seller's address.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct CoinPayout {
    pub pair: u8,
    pub to: String,
    /// atomic, still to burn
    pub left: u64,
    /// atomic, already handed to custody
    #[serde(default)]
    pub sent: u64,
    /// the burn in flight: its note's nullifier and rung
    #[serde(default)]
    pub burning: Option<(String, u64)>,
    pub created_ms: u64,
    /// ⭐ AUTO-OPSEC (user 2026-11-10), the wallet's one privacy setting as it stood when this payout started. On: every rung
    /// is paid to an address of its own where the coin's chain is public (this wallet's Bitcoin vault) and each in its own
    /// later payout slot, the sealed pay-after the cash-out lane draws. Off (the user passed the warning): the address
    /// given, at once. MEASURED (`swap_linkability`, both public chains read): every rung to one address at once names
    /// its deposit for 90 to 100 of 100 pieces; a fresh address and its own slot inside a day, about 2 of 100 at 100 users
    /// a day and 2 of 10,000 at 10,000.
    #[serde(default)]
    pub opsec: bool,
    /// the rung in flight or next: where it pays, its sealed pay-after (chain ms, 0 = at once) and its vault index — drawn
    /// once and kept until that rung's burn is on the chain, so a burn built again names the same address and delay
    #[serde(default)]
    pub next_to: Option<String>,
    #[serde(default)]
    pub next_pay_after: u64,
    #[serde(default)]
    pub next_vault: Option<u32>,
    /// the pay-afters of the rungs already handed to custody that are still ahead (a new rung never joins their slot)
    #[serde(default)]
    pub handed_after: Vec<u64>,
}

/// A rung this wallet's vault was paid by a sell: kept for good (the address is the user's coin; the index line never
/// hands it out again).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct VaultRung {
    pub index: u32,
    pub address: String,
    /// atomic units of the coin
    pub amount: u64,
    pub pay_after: u64,
    pub created_ms: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct DefiFile {
    orders: Vec<DefiOrder>,
    intents: Vec<SatIntent>,
    next_nonce: u64,
    /// ⭐ spec §18.12 — orders waiting for their exact-amount note (the payment to self that makes it is out)
    #[serde(default)]
    exact: Vec<ExactOrder>,
    #[serde(default)]
    payouts: Vec<CoinPayout>,
    /// every rung a sell paid to this wallet's own vault (bounded by what the user sold; each is one coin of theirs)
    #[serde(default)]
    vault_rungs: Vec<VaultRung>,
    /// ⭐ EARN — this wallet's positions in the pools (bounded by what the user deposited)
    #[serde(default)]
    positions: Vec<PositionRec>,
}

/// The highest vault index a sell's payout ever drew (the vault's one index line, `vault_next_index`).
pub(crate) fn max_vault_index() -> Option<u32> {
    let f = read_defi();
    f.vault_rungs.iter().map(|v| v.index).chain(f.payouts.iter().filter_map(|p| p.next_vault)).max()
}

/// An order waiting for a note of exactly its amount (spec §18.12: an order spends a note of exactly its amount).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ExactOrder {
    pub pair: u8,
    pub sell: bool,
    #[serde(default)]
    pub payout: Option<String>,
    pub amount: u64,
    pub bucket: usize,
    pub created_ms: u64,
    /// whether the note exists or its payment to self is out; false: this order waited on the market first and still has to make it
    #[serde(default = "yes")]
    pub prepared: bool,
    /// ⭐ EARN — a SAT deposit waiting for its exact note
    #[serde(default)]
    pub deposit: bool,
}

fn yes() -> bool {
    true
}

/// The error an order without an exact-amount note returns (the caller makes one by a payment to itself).
const NEED_EXACT: &str = "NEED_EXACT_NOTE";

fn defi_path() -> Option<PathBuf> {
    let kid = current_key_id_hex()?;
    let cid = current_chain_id();
    let cid = if cid.is_empty() { "nochain".to_string() } else { cid };
    Some(node_data_dir().join(format!("v2wallet-defi-{}-{}.json", &kid[..kid.len().min(16)], &cid[..cid.len().min(16)])))
}
fn read_defi() -> DefiFile {
    let f: DefiFile = defi_path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    note_order_inputs(&f);
    f
}
fn write_defi(f: &DefiFile) -> Result<(), String> {
    // the open orders' inputs are reserved before the list is saved: every caller writes after the node admitted the order
    note_order_inputs(f);
    let p = defi_path().ok_or("no wallet open")?;
    let bytes = serde_json::to_vec(f).map_err(|e| format!("the order list did not encode: {e}"))?;
    std::fs::write(p, bytes).map_err(|e| format!("the order list could not be saved: {e}"))
}

/// ⭐ THE NOTES THIS WALLET'S OPEN ORDERS SPEND — no other spender may choose one (`spendable_now` reads this). An order spends
/// its note only when custody carries it into a batch's slots and a block shows that, so until then the note looked spendable
/// to every selection in this wallet. MEASURED 2026-11-10 (launch_trade.py round 21, real nodes): the BTC and the XMR sell of
/// 40 SAT each were placed in one pass, the second found the same first 40-SAT note the first had just committed, the BTC
/// sell's slot spent it, and every copy of the XMR sell since was refused at custody as spent (`NullifierSpent`) while its own
/// 40-SAT note sat unused — an order that could never complete. BORROWED: Bitcoin Core's wallet, where the inputs of its own
/// unconfirmed transactions are spent for coin selection the moment it accepts them (the wallet's transaction store is the
/// record, here the order file). Derived from the order file only, by its one reader and writer, so it survives a restart
/// exactly as the file does; reset with the rest of a wallet's state (`clear_order_inputs`). A RAM shape: nothing new is stored.
/// O1-FOOTPRINT-REVIEWED: one 32-byte value per open order of this wallet, the order list's own bound.
static ORDER_INPUTS: std::sync::Mutex<Option<std::collections::HashSet<[u8; 32]>>> = std::sync::Mutex::new(None);

fn note_order_inputs(f: &DefiFile) {
    let set = f
        .orders
        .iter()
        .filter_map(|o| o.input_nf.as_deref())
        .filter_map(|h| hex::decode(h).ok())
        .filter_map(|v| <[u8; 32]>::try_from(v).ok())
        .collect();
    *ORDER_INPUTS.lock().unwrap_or_else(|e| e.into_inner()) = Some(set);
}

/// Whether `nf` is the note one of this wallet's open orders spends (a leaf lock: no file, wallet or scan lock is taken).
pub(crate) fn is_order_input(nf: &[u8; 32]) -> bool {
    ORDER_INPUTS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|s| s.contains(nf))
}

/// Load the open orders' inputs of the wallet just opened (`reset_scan`, after its keys are installed).
pub(crate) fn prime_order_inputs() {
    let _ = read_defi();
}

/// A wallet's orders are its own: they leave with it (`reset_locator_state`).
pub(crate) fn clear_order_inputs() {
    *ORDER_INPUTS.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Test builds: file one open sell of `x` spending the note `input_nf` through the order file's one writer, as `deal_order`
/// does once the node admitted it.
#[cfg(test)]
pub(crate) fn file_open_order_for_tests(input_nf: [u8; 32], x: u64) -> Result<(), String> {
    let mut f = read_defi();
    f.orders.push(DefiOrder {
        pair: 1,
        sell: true,
        payout: None,
        nonce: f.next_nonce,
        batch: u64::MAX,
        input_nf: Some(hex::encode(input_nf)),
        sent_batch: 0,
        amount: x,
        created_ms: now_ms(),
        status: "open".into(),
        tick: None,
        j_min: 0,
        sells: false,
        out: 0,
        bucket: 0,
        kind: String::new(),
        position: None,
        earn: false,
        dep: false,
        index: 0,
        claim2_hex: None,
        claim2_cm: None,
        claim_hex: None,
        claim_cm: None,
        claim_sent_ms: 0,
        claim_batch: 0,
        claim_prev: Vec::new(),
    });
    f.next_nonce += 1;
    write_defi(&f)
}

/// The order's secret: its amount's blind (8 lanes below 2^30, field elements of the commitment), derived from this wallet's
/// outgoing-record secret and the order's index.
fn amount_blind_for(out_sk: &[u8; 32], nonce: u64) -> [u64; 8] {
    let mut h = blake3::Hasher::new_keyed(out_sk);
    h.update(b"MUSD/defi-order/amount-blind/v1");
    h.update(&nonce.to_le_bytes());
    let b = h.finalize();
    core::array::from_fn(|i| u64::from(u32::from_le_bytes(b.as_bytes()[4 * i..4 * i + 4].try_into().unwrap_or([0; 4]))) & ((1 << 30) - 1))
}

fn post(path: &str, body: serde_json::Value, secs: u64) -> Result<serde_json::Value, String> {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(secs))
        .build()
        .post(&format!("{}{path}", node_url()))
        .send_json(body)
        .map_err(|e| format!("the node did not answer: {}", node_refusal(e)))?
        .into_json()
        .map_err(|e| format!("the node's answer: {e}"))
}

/// The pool of a coin's name.
fn pair_of(coin: &str) -> Result<u8, String> {
    match coin.trim().to_uppercase().as_str() {
        "BTC" => Ok(0),
        "XMR" => Ok(1),
        _ => Err("SAT trades against Bitcoin or Monero".into()),
    }
}
fn coin_name(pair: u8) -> &'static str {
    if pair == 0 { "BTC" } else { "XMR" }
}
/// The coin's ledger on this chain.
fn coin_ledger(pair: u8) -> u32 {
    if pair == 0 { usdmd_node::peg::COIN_BTC_ASSET_ID } else { usdmd_node::peg::COIN_XMR_ASSET_ID }
}
/// The coin's atoms per whole coin.
fn coin_unit(pair: u8) -> f64 {
    if pair == 0 { 1e8 } else { 1e12 }
}
const SAT_UNIT: f64 = 1e8;

/// The price at tick `t`, in whole coin per whole SAT.
fn coin_per_sat(pair: u8, t: i64) -> f64 {
    let (n, d) = usdmd_node::defi_clear::tick_ratio(t);
    n as f64 / d as f64 * SAT_UNIT / coin_unit(pair)
}

/// The whole coin `sat` whole SAT sells for at tick `t`: `⌊(x − ⌈x·f⌉) · n_t / d_t⌋`, what a sell's claim pays — its SAT less
/// the 0.2 % fee on the SAT leg (Earn step 1, `br15_audit::sell_paid`).
fn coin_at(pair: u8, sat: f64, t: i64) -> f64 {
    let (n, d) = usdmd_node::defi_clear::tick_ratio(t);
    ba::sell_paid((sat * SAT_UNIT) as u64, n, d).unwrap_or(0) as f64 / coin_unit(pair)
}

/// The SAT atoms `coin_atomic` buys at the batch tick `t`: its fill `g = ⌊y · d_{t+1} / n_{t+1}⌋` less the 0.2 % fee `⌈g·f⌉`
/// (Earn step 1, `br15_audit::buy_paid`) — exactly what the claim relation pays.
fn sat_at(coin_atomic: u64, t: i64) -> u64 {
    let (n1, d1) = usdmd_node::defi_clear::tick_ratio(t + 1);
    ba::buy_paid(coin_atomic, d1, n1).unwrap_or(0)
}

/// The maximum price of each bucket over a batch opened at tick `t`, in whole coin per SAT (`None` for the last: no maximum).
fn bucket_prices(pair: u8, t: i64) -> Vec<Option<f64>> {
    usdmd_node::defi_clear::BUCKET_TICKS.iter().map(|d| d.map(|d| coin_per_sat(pair, t + d))).collect()
}

/// ⭐ THE BOOK, for the trade screen: open, taking orders, the last price in the coin, what `quote_coin` whole coin buys at it and what `quote_sat` whole SAT sells for,
/// and the maximum-price choices a buy's confirmation offers.
pub(crate) fn defi_book_blocking(coin: String, quote_coin: f64, quote_sat: f64) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let b = post("/defi_book", serde_json::json!({ "pair": pair }), 10)?;
    let open = b["open"].as_bool() == Some(true);
    let t = b["last_tick"].as_i64().ok_or("the node's book names no tick")?;
    let buys = if quote_coin > 0.0 { sat_at((quote_coin * coin_unit(pair)) as u64, t) as f64 / SAT_UNIT } else { 0.0 };
    let sells = if quote_sat > 0.0 { coin_at(pair, quote_sat, t) } else { 0.0 };
    let closes_at = b["closes_at"].as_u64().ok_or("the node's book names no close")?;
    let held = |tag: [u64; 3]| -> u64 {
        let spent = PROVEN_SPENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let s = SCAN.lock().unwrap_or_else(|e| e.into_inner());
        s.as_ref().map_or(0, |st| st.owned.iter().filter(|n| n.asset == tag && spendable_now(&st.spent, &st.pending_change, &spent, n.amount, n.seed, &n.nf)).map(|n| n.amount).sum())
    };
    Ok(serde_json::json!({
        "coin": coin_name(pair),
        "coin_held": held(db::pair_y_tag(pair)) as f64 / coin_unit(pair),
        "sat_held": held(usdmd_node::satoshi::asset_tag()) as f64 / SAT_UNIT,
        "open": open,
        "taking_orders": b["taking_orders"].as_bool() == Some(true),
        "batch": b["batch"],
        "price_coin_per_sat": coin_per_sat(pair, t),
        "quote_sat": buys,
        "quote_coin": sells,
        "last_expired": b["last_expired"],
        "last_sells": b["last_sells"],
        // ⭐ EARN — the batch a withdrawal settles in (every EARN_EVERY-th) and the pool's public income index
        "earn_next": b["earn_next"],
        "earn_every": usdmd_node::defi_earn::EARN_EVERY,
        "closes_in_blocks": closes_at.saturating_sub(b["score"].as_u64().ok_or("the node's book names no score")?),
        "max_prices": bucket_prices(pair, t),
        "max_percent": [2, 10, 50, serde_json::Value::Null],
        "default_bucket": usdmd_node::defi_clear::DEFAULT_BUCKET,
        // spec §18.13: the launch pool is a PUBLIC donation, locked for ever (no key withdraws it) — what the Buy screen states
        "launch_donation_sat": usdmd_node::defi_launch::LAUNCH_DONATION_SAT,
    }))
}

/// ⭐ §18.15 THE CHART'S DATA: a pair's prices over the last `range_secs` (0 = all it holds), at the finest resolution that spans it, each `[seconds, whole coin per SAT]`, the live price last.
/// DIGITAL-CASH-PRIVACY-REVIEWED: asked of this wallet's own node only; the closed list's one price per batch, no volume, depth or order.
pub(crate) fn defi_prices_blocking(coin: String, range_secs: u64) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let r = post("/defi_prices", serde_json::json!({ "pair": pair }), 10)?;
    let live = r["last_tick"].as_i64().ok_or("the node's history names no tick")?;
    let now = now_ms() / 1000;
    let since = if range_secs == 0 { 0 } else { now.saturating_sub(range_secs) };
    let levels = r["levels"].as_array().cloned().unwrap_or_default();
    let spans = |ring: &serde_json::Value| ring.as_array().and_then(|a| a.first()).and_then(|p| p[0].as_u64()).is_some_and(|first| first <= since) || ring.as_array().is_some_and(|a| a.len() < usdmd_node::defi_batch::PRICE_POINTS);
    let ring = levels.iter().find(|l| spans(l)).or_else(|| levels.last());
    let mut points: Vec<serde_json::Value> = ring
        .and_then(|l| l.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| Some((p[0].as_u64()?, p[1].as_i64()?)))
                .filter(|(s, _)| *s >= since)
                .map(|(s, t)| serde_json::json!([s, coin_per_sat(pair, t)]))
                .collect()
        })
        .unwrap_or_default();
    points.push(serde_json::json!([now, coin_per_sat(pair, live)]));
    Ok(serde_json::json!({ "coin": coin_name(pair), "points": points, "price_coin_per_sat": coin_per_sat(pair, live) }))
}

/// The asset an order of this side spends.
fn spend_tag(pair: u8, sell: bool) -> [u64; 3] {
    if sell { usdmd_node::satoshi::asset_tag() } else { db::pair_y_tag(pair) }
}

/// ⭐ PLACE ONE ORDER of `x` atomic at maximum-price bucket `bucket` in the open batch of `pair`: the dealing, the note of exactly `x`, its member leg — relayed to this wallet's node.
/// The chain sees neither side nor amount (§18.14). Nothing is spent unless the node admits it.
fn place_order(pair: u8, sell: bool, payout: Option<String>, x: u64, bucket: usize) -> Result<DefiOrder, String> {
    deal_order(pair, sell, payout, x, bucket, None, false)
}

fn place_order_kind(pair: u8, sell: bool, payout: Option<String>, x: u64, bucket: usize, deposit: bool) -> Result<DefiOrder, String> {
    deal_order(pair, sell || deposit, payout, x, bucket, None, deposit)
}

/// ⭐ EARN — an order's limit commitment by its kind: a trade's side code, a deposit's code, a withdrawal's code with the entry
/// index its position carries (what the leaf of its batch names, and what its claim opens).
fn order_limit_commit(o: &DefiOrder, blind: &[u64; 8]) -> [u64; 8] {
    match (o.kind.as_str(), &o.position) {
        ("deposit", _) => ba::limit_commit_x(ba::kind_code(o.bucket as u64, true, true), blind, o.index, 0),
        ("withdraw", Some(p)) => ba::limit_commit_x(o.bucket as u64 + ba::WITHDRAW_BUCKET_BASE, blind, position_witness(p).entry_index(), o.index),
        _ => ba::limit_commit(ba::side_bucket(o.bucket as u64, o.sell), blind),
    }
}

/// A position's witness for the order and claim relations (its blind re-derived from the words).
pub(crate) fn position_witness(p: &PositionRec) -> ba::PositionWitness {
    let out_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).unwrap_or([0; 32]);
    let x_blind = amount_blind_for(&out_sk, p.nonce);
    let (p_num, p_den, j_min, s_num, s_den) = if p.j_min >= ba::ORDER_BUCKETS as u64 && !p.sells {
        (1, 1, ba::ORDER_BUCKETS as u64, 0, 1)
    } else {
        let (n1, d1) = usdmd_node::defi_clear::tick_ratio(p.tick + 1);
        let (sn, sd) = db::sell_price(p.tick, p.sells);
        (d1, n1, p.j_min, sn, sd)
    };
    ba::PositionWitness {
        x: p.x,
        x_blind,
        bucket: p.bucket,
        from_withdrawal: p.from_withdrawal,
        entry: p.entry,
        now: p.now,
        p_num,
        p_den,
        j_min,
        s_num,
        s_den,
        extra: ba::LeafExtra { earn: false, dep: p.dep },
    }
}

/// ⭐ One order dealt and handed to custody. `again` names an order already placed: the same secret and the same note, so its amount and limit commitments are the old ones, whichever copy is carried claims the same way, and the nullifier lets only one land.
fn deal_order(pair: u8, sell: bool, payout: Option<String>, x: u64, bucket: usize, again: Option<(u64, [u8; 32])>, deposit: bool) -> Result<DefiOrder, String> {
    if bucket >= ba::ORDER_BUCKETS {
        return Err("that maximum price is not one of the choices — nothing was spent".into());
    }
    use rand::RngCore as _;
    let b = post("/defi_book", serde_json::json!({ "pair": pair }), 10)?;
    if b["open"].as_bool() != Some(true) {
        return Err("the SAT market is not open on this chain yet — nothing was spent".into());
    }
    if b["taking_orders"].as_bool() != Some(true) {
        return Err("the custody set is handing the pool over — orders resume in seconds; nothing was spent".into());
    }
    // ⭐ EARN — an Earn batch clears no trade and takes no deposit (each would come back): they wait for the next batch
    if b["batch"].as_u64().is_some_and(usdmd_node::defi_earn::is_earn_batch) {
        return Err("the pool's Earn batch is open (it pays withdrawals only) — this goes in the next batch, in seconds; nothing was spent".into());
    }
    // ⭐ EARN STEP 3 — a deposit counts only in the pool's DEPOSIT batch (the first to open after each hour's income posts):
    // anywhere else it would come back whole, so it waits here, nothing spent, and goes out the moment that batch opens
    if deposit && b["deposit_batch"].as_bool() != Some(true) {
        return Err("a deposit waits for the pool's next deposit batch (the first after each hour's income posts) — nothing was spent".into());
    }
    // ⭐ EARN STEP 3 — the order carries the index its batch opened at (the slots refuse it in a batch that opened at another)
    let index = b["batch_index"].as_u64().ok_or("the node's book names no batch index — nothing was spent")?;
    let t = b["t"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("the node's book names no threshold")?;
    let eks: Vec<Vec<u8>> = b["eks_hex"]
        .as_array()
        .ok_or("the book names no custody keys")?
        .iter()
        .map(|k| k.as_str().and_then(|h| hex::decode(h).ok()).ok_or("a custody key is not hex"))
        .collect::<Result<_, _>>()?;
    // the custody epoch whose released key wraps the shares (forward secrecy: erased two epochs on)
    let seal = &b["seal_epoch"];
    let epoch = seal["epoch"].as_u64().ok_or("the custody's first key is still forming — try again in a minute; nothing was spent")?;
    let epoch_b = seal["b_hex"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|v| usdmd_node::epoch_key::unpack_b(&v)).ok_or("the node's epoch key does not decode — nothing was spent")?;
    let epoch_pk = usdmd_node::epoch_key::EpochPublicKey {
        seed: usdmd_node::epoch_deal_tx::matrix_seed(epoch),
        b: epoch_b.b,
        contributors: seal["contributors"].as_u64().and_then(|c| u32::try_from(c).ok()).ok_or("the node's epoch key names no contributors")?,
    };
    let (out_sk, keys) = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.out_sk, w.note_keys())
    };
    // A restored wallet's slot claim spends a held note: nothing else may spend one until the slot is settled, or the two would race for it
    if slot_status() != note_store::SlotStatus::Decided {
        return Err("this wallet's device slot is still settling — nothing was spent".into());
    }
    // ⭐ §18.12: the order spends ONE note of exactly its amount
    let tag = spend_tag(pair, sell);
    let (in_seed, input_nf) = {
        let held = PROVEN_SPENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let s = SCAN.lock().unwrap_or_else(|e| e.into_inner());
        s.as_ref()
            .and_then(|st| {
                st.owned
                    .iter()
                    .find(|n| match again {
                        Some((_, nf)) => n.nf == nf && !held.contains(&nf),
                        None => n.asset == tag && n.amount == x && spendable_now(&st.spent, &st.pending_change, &held, n.amount, n.seed, &n.nf),
                    })
                    .map(|n| (n.seed, n.nf))
            })
            .ok_or(NEED_EXACT)?
    };
    let mut file = read_defi();
    let nonce = again.map_or(file.next_nonce, |(n, _)| n);
    let a_blind = amount_blind_for(&out_sk, nonce);
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let in_owner = keys.owner(in_seed);
    let owner = [in_owner.ask, in_owner.nk, in_owner.seed];
    let lc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was spent")?;
    // ⭐ EARN — a SAT deposit is an order of its own kind (half sold through the batch, the rest joining the pool)
    let kind = if deposit { usdmd_node::defi_custody::OrderKind::Deposit } else { usdmd_node::defi_custody::OrderKind::Trade { sell } };
    let (dealing, share_commits, epoch_ct, sealed, share_proof) =
        usdmd_node::defi_custody::order_parts_kind(pair, kind, &eks, t, epoch, &epoch_pk, x, bucket, a_blind, owner, lc_blind, index, &key)
            .ok_or("the order's shares could not be dealt — nothing was spent")?;
    let (cm, nf, lc) = dealing.spend_publics();
    if leaf4_to_bytes(nf) != input_nf {
        return Err("refusing: the order does not spend the note it names — nothing was spent".into());
    }
    let reservation = if again.is_none() { Some(reserve_chg_indices(0, &[input_nf])?) } else { None };
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let (mem_hex, tip_hex) = defi_slot_leg(&agent, &leaf4_to_bytes(cm), nf, lc_blind).ok_or("the note's membership cannot be proved yet — nothing was spent")?;
    let order = db::DefiOrderTx {
        pair,
        amount_commit: dealing.amount_commit(),
        limit_commit: dealing.limit_commit(),
        share_commits,
        epoch,
        epoch_ct,
        sealed,
        share_proof,
        nullifier: nf,
        leaf_commit: lc,
        member_carrier: hex::decode(&mem_hex).map_err(|e| format!("member leg hex: {e}"))?,
        member_tuple: hex::decode(&tip_hex).map_err(|e| format!("member tip hex: {e}"))?,
        index,
    };
    if order.self_valid(t).is_some() {
        return Err("refusing: the order does not verify against its own proofs — nothing was spent".into());
    }
    let bytes = order.encode().ok_or("the order did not encode — nothing was spent")?;
    let r = post("/submit_defi_order", serde_json::json!({ "object_hex": hex::encode(bytes) }), 30)?;
    if r["verdict"].as_str() != Some("HANDED_TO_CUSTODY") {
        return Err(format!("the node refused the order (nothing was spent): {}", r["reason"].as_str().unwrap_or("no reason named")));
    }
    if let Some(r) = reservation {
        r.commit(input_nf);
    }
    // the batch is the one whose slots carry it (learned from the book: `u64::MAX` until then)
    let o = DefiOrder {
        pair,
        sell,
        payout,
        nonce,
        batch: u64::MAX,
        input_nf: Some(hex::encode(input_nf)),
        sent_batch: b["batch"].as_u64().unwrap_or(0),
        amount: x,
        created_ms: now_ms(),
        status: "open".into(),
        tick: None,
        j_min: 0,
        sells: false,
        out: 0,
        bucket,
        claim_hex: None,
        claim_cm: None,
        claim_sent_ms: 0,
        claim_batch: 0,
        claim_prev: Vec::new(),
        kind: if deposit { "deposit".into() } else { String::new() },
        position: None,
        earn: false,
        dep: false,
        index,
        claim2_hex: None,
        claim2_cm: None,
    };
    if again.is_some() {
        return Ok(o);
    }
    file.next_nonce = nonce + 1;
    file.orders.push(o.clone());
    write_defi(&file)?;
    Ok(o)
}

/// ⭐ An order of `x` at `bucket`, or — with no note of exactly `x` — the payment to itself that makes one, the order then waiting for that note (`defi_progress_blocking` places it the moment it is owned).
fn place_or_prepare(pair: u8, sell: bool, payout: Option<String>, x: u64, bucket: usize) -> Result<serde_json::Value, String> {
    place_or_prepare_kind(pair, sell, payout, x, bucket, false)
}

fn place_or_prepare_kind(pair: u8, sell: bool, payout: Option<String>, x: u64, bucket: usize, deposit: bool) -> Result<serde_json::Value, String> {
    let sell = sell || deposit;
    match place_order_kind(pair, sell, payout.clone(), x, bucket, deposit) {
        Ok(_) => Ok(serde_json::json!({ "placed": true })),
        Err(why) if why == NEED_EXACT => {
            let me = wallet_address()?["address"].as_str().map(str::to_string).ok_or("this wallet has no address")?;
            wallet_send_asset_atomic_blocking(&me, spend_tag(pair, sell), x, if sell { "SAT" } else { coin_name(pair) })?;
            let mut f = read_defi();
            f.exact.push(ExactOrder { pair, sell, payout, amount: x, bucket, created_ms: now_ms(), prepared: true, deposit });
            write_defi(&f)?;
            Ok(serde_json::json!({ "placed": false, "preparing": true }))
        }
        // trading never stops for these: a handover or a key still forming lasts moments, so the order waits here and goes out on its own, nothing spent
        Err(why)
            if why.contains("handing the pool over")
                || why.contains("first key is still forming")
                || why.contains("membership cannot be proved yet")
                || why.contains("device slot is still settling")
                || why.contains("Earn batch is open")
                || why.contains("next deposit batch") =>
        {
            let mut f = read_defi();
            f.exact.push(ExactOrder { pair, sell, payout, amount: x, bucket, created_ms: now_ms(), prepared: false, deposit });
            write_defi(&f)?;
            // ⭐ EARN STEP 3 — a deposit waiting for the pool's hourly deposit batch says so (the screen names the wait, not a note)
            let waiting = if why.contains("next deposit batch") { "deposit_batch" } else { "moment" };
            Ok(serde_json::json!({ "placed": false, "preparing": true, "waiting": waiting }))
        }
        Err(why) => Err(why),
    }
}

/// ⭐ §18.14 BUY SAT WITH COIN THIS WALLET ALREADY HOLDS: one sealed order of `amount` whole coin at maximum-price bucket `max_bucket`.
pub(crate) fn buy_sat_blocking(coin: String, amount: f64, max_bucket: usize) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let x = (amount * coin_unit(pair)).round() as u64;
    if x == 0 {
        return Err("enter a positive amount — nothing was spent".into());
    }
    place_or_prepare(pair, false, None, x, max_bucket)
}

/// ⭐ §18.14 BUY SAT WITH BITCOIN OR MONERO: a deposit of `amount` whole coin that mints a coin note atom for atom (no backing ratio, no price read); the order is placed the moment it does (`defi_progress_blocking`).
pub(crate) fn buy_sat_deposit_blocking(coin: String, amount: f64, max_bucket: usize) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    if max_bucket >= ba::ORDER_BUCKETS {
        return Err("that maximum price is not one of the choices".into());
    }
    let atomic = (amount * coin_unit(pair)).round() as u64;
    let r = coin_deposit_start(coin_name(pair), atomic)?;
    let swap_id = r["swap_id"].as_str().ok_or("the deposit has no id")?.to_string();
    let mut f = read_defi();
    f.intents.push(SatIntent { swap_id, pair, amount: atomic, bucket: max_bucket, created_ms: now_ms(), status: "waiting".into() });
    write_defi(&f)?;
    Ok(r)
}

// ───────────────────────────── EARN: deposits, positions, withdrawals ─────────────────────────────

/// ⭐ EARN — DEPOSIT `sat` whole SAT into `coin`'s pool (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md): one sealed order of the
/// deposit kind — half of it is sold through the batch like any sell (its fee and price as a sell's), the rest joins the pool
/// with the coin that half earned. It counts exactly when its batch's sells do; then its batch's leaf is this wallet's
/// POSITION (`earn_positions_blocking`). Otherwise it comes back whole. It never rides an Earn batch (it would come back).
pub(crate) fn earn_deposit_blocking(coin: String, sat: f64) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let x = (sat * SAT_UNIT).round() as u64;
    if x < 2 {
        return Err("enter a positive amount of SAT — nothing was spent".into());
    }
    place_or_prepare_kind(pair, true, None, x, 0, true)
}

/// ⭐ EARN — what a deposit of `sat` SAT into `coin`'s pool would hold at the pool's LAST tick, before anything is spent: the
/// half sold and the coin it earns, the position's units, and what withdrawing those units would pay at that same tick (SAT
/// and coin, each at most the units' share). The gap between the deposit and that withdrawal is the deposit's whole cost
/// (the fee on its sold half, and the rounding toward the pool), so the screen shows it in dollars before the user acts.
/// Read only: the node's public book and this wallet's arithmetic (`defi_earn`), the same terms the decider proves.
pub(crate) fn earn_quote_blocking(coin: String, sat: f64) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let x = (sat * SAT_UNIT).round() as u64;
    let b = post("/defi_book", serde_json::json!({ "pair": pair }), 10)?;
    let t = b["last_tick"].as_i64().ok_or("the node's book names no price yet")?;
    let d = usdmd_node::defi_earn::deposit_terms(x, t).ok_or("that deposit is too small to sell a unit")?;
    let (w_sat, w_coin) = usdmd_node::defi_earn::withdraw_terms(d.units, t).unwrap_or((0, 0));
    Ok(serde_json::json!({
        "coin": coin_name(pair),
        "deposit_sat": x as f64 / SAT_UNIT,
        "sold_sat": d.sold as f64 / SAT_UNIT,
        "sold_for_coin": d.coin as f64 / coin_unit(pair),
        "units": d.units,
        "withdraw_sat": w_sat as f64 / SAT_UNIT,
        "withdraw_coin": w_coin as f64 / coin_unit(pair),
        "price_coin_per_sat": coin_per_sat(pair, t),
        "earn_next": b["earn_next"],
        "batch": b["batch"],
    }))
}

/// The custody set's keys and epoch, as an order seals to them (the book, threshold, custody keys, epoch, epoch key).
fn custody_seal(pair: u8) -> Result<(serde_json::Value, u32, Vec<Vec<u8>>, u64, usdmd_node::epoch_key::EpochPublicKey), String> {
    let b = post("/defi_book", serde_json::json!({ "pair": pair }), 10)?;
    if b["open"].as_bool() != Some(true) {
        return Err("the SAT market is not open on this chain yet — nothing was spent".into());
    }
    if b["taking_orders"].as_bool() != Some(true) {
        return Err("the custody set is handing the pool over — orders resume in seconds; nothing was spent".into());
    }
    let t = b["t"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("the node's book names no threshold")?;
    let eks: Vec<Vec<u8>> = b["eks_hex"]
        .as_array()
        .ok_or("the book names no custody keys")?
        .iter()
        .map(|k| k.as_str().and_then(|h| hex::decode(h).ok()).ok_or("a custody key is not hex"))
        .collect::<Result<_, _>>()?;
    let seal = &b["seal_epoch"];
    let epoch = seal["epoch"].as_u64().ok_or("the custody's first key is still forming — try again in a minute; nothing was spent")?;
    let epoch_b = seal["b_hex"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|v| usdmd_node::epoch_key::unpack_b(&v)).ok_or("the node's epoch key does not decode — nothing was spent")?;
    let epoch_pk = usdmd_node::epoch_key::EpochPublicKey {
        seed: usdmd_node::epoch_deal_tx::matrix_seed(epoch),
        b: epoch_b.b,
        contributors: seal["contributors"].as_u64().and_then(|c| u32::try_from(c).ok()).ok_or("the node's epoch key names no contributors")?,
    };
    Ok((b, t, eks, epoch, epoch_pk))
}

/// ⭐ EARN — ONE WITHDRAWAL of a position's whole units: a sealed order of the withdrawal kind spending the position (its leaf,
/// under its position nullifier — no note), placed while the pair's EARN batch takes orders. Paid there in two claims (its SAT
/// with its income, and its coin); a batch that pays nothing leaves its units in a new position, withdrawn again next time.
fn place_withdrawal(rec: &PositionRec) -> Result<DefiOrder, String> {
    place_withdrawal_at(rec, None)
}

/// [`place_withdrawal`], or — `again` naming a withdrawal a batch passed by — the same withdrawal dealt again under its own
/// nonce (the same blind, so the same amount commitment and the same position nullifier: whichever copy lands, only one
/// spends the position, and this wallet's record finds its leaf).
fn place_withdrawal_at(rec: &PositionRec, again: Option<u64>) -> Result<DefiOrder, String> {
    use rand::RngCore as _;
    let (b, t, eks, epoch, epoch_pk) = custody_seal(rec.pair)?;
    if !b["batch"].as_u64().is_some_and(usdmd_node::defi_earn::is_earn_batch) {
        return Err("a withdrawal waits for the pool's Earn batch (every eighth) — nothing was spent".into());
    }
    // ⭐ EARN STEP 3 — a window closed and its income not posted yet: a withdrawal now would be paid at the index before it
    // (the closed hour's income would stay in the pool), so it waits for the Earn batch after the income posts
    if b["raise_pending"].as_bool() == Some(true) {
        return Err("a withdrawal waits for the pool's Earn batch after this hour's income posts — nothing was spent".into());
    }
    let index = b["batch_index"].as_u64().ok_or("the node's book names no batch index — nothing was spent")?;
    let out_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).ok_or("no wallet open")?;
    let pw = position_witness(rec);
    let units = pw.units_max().filter(|u| *u > 0).ok_or("this position has nothing to withdraw")?;
    let mut file = read_defi();
    let nonce = again.unwrap_or(file.next_nonce);
    let a_blind = amount_blind_for(&out_sk, nonce);
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let lc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was spent")?;
    let (dealing, share_commits, epoch_ct, sealed, share_proof) =
        usdmd_node::defi_custody::order_parts_kind(rec.pair, usdmd_node::defi_custody::OrderKind::Withdraw(pw), &eks, t, epoch, &epoch_pk, units, 0, a_blind, [[0; 8]; 3], lc_blind, index, &key)
            .ok_or("the withdrawal's shares could not be dealt — nothing was spent")?;
    let (cm, nf, lc) = dealing.spend_publics();
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let (mem_hex, tip_hex) = defi_slot_leg(&agent, &leaf4_to_bytes(cm), nf, lc_blind).ok_or("the position's membership cannot be proved yet — nothing was spent")?;
    let order = db::DefiOrderTx {
        pair: rec.pair,
        amount_commit: dealing.amount_commit(),
        limit_commit: dealing.limit_commit(),
        share_commits,
        epoch,
        epoch_ct,
        sealed,
        share_proof,
        nullifier: nf,
        leaf_commit: lc,
        member_carrier: hex::decode(&mem_hex).map_err(|e| format!("member leg hex: {e}"))?,
        member_tuple: hex::decode(&tip_hex).map_err(|e| format!("member tip hex: {e}"))?,
        index,
    };
    if order.self_valid(t).is_some() {
        return Err("refusing: the withdrawal does not verify against its own proofs — nothing was spent".into());
    }
    let bytes = order.encode().ok_or("the withdrawal did not encode — nothing was spent")?;
    let r = post("/submit_defi_order", serde_json::json!({ "object_hex": hex::encode(bytes) }), 30)?;
    if r["verdict"].as_str() != Some("HANDED_TO_CUSTODY") {
        return Err(format!("the node refused the withdrawal (nothing was spent): {}", r["reason"].as_str().unwrap_or("no reason named")));
    }
    let o = DefiOrder {
        pair: rec.pair,
        sell: false,
        payout: None,
        nonce,
        batch: u64::MAX,
        input_nf: Some(hex::encode(leaf4_to_bytes(nf))),
        sent_batch: b["batch"].as_u64().unwrap_or(0),
        amount: units,
        created_ms: now_ms(),
        status: "open".into(),
        tick: None,
        j_min: 0,
        sells: false,
        out: 0,
        bucket: 0,
        claim_hex: None,
        claim_cm: None,
        claim_sent_ms: 0,
        claim_batch: 0,
        claim_prev: Vec::new(),
        kind: "withdraw".into(),
        position: Some(rec.clone()),
        earn: false,
        dep: false,
        index,
        claim2_hex: None,
        claim2_cm: None,
    };
    if again.is_some() {
        return Ok(o);
    }
    file.next_nonce = nonce + 1;
    file.orders.push(o.clone());
    write_defi(&file)?;
    Ok(o)
}

/// ⭐ EARN — WITHDRAW position `index` (as `earn_positions_blocking` lists it): its whole units, at the pool's next Earn batch
/// (placed now if that batch is open, else the moment it is, by `defi_progress_blocking`).
pub(crate) fn earn_withdraw_blocking(index: usize) -> Result<serde_json::Value, String> {
    let mut f = read_defi();
    let p = f.positions.get_mut(index).ok_or("there is no such position")?;
    if p.status != "open" && p.status != "withdrawing" {
        return Err("that position is already being withdrawn".into());
    }
    p.status = "withdrawing".into();
    let rec = p.clone();
    write_defi(&f)?;
    match place_withdrawal(&rec) {
        Ok(_) => {
            let mut f = read_defi();
            f.positions.retain(|q| q != &PositionRec { status: "withdrawing".into(), ..rec.clone() });
            write_defi(&f)?;
            Ok(serde_json::json!({ "placed": true }))
        }
        Err(why) if why.contains("waits for the pool's Earn batch") || why.contains("cannot be proved yet") || why.contains("handing the pool over") || why.contains("still forming") => {
            Ok(serde_json::json!({ "placed": false, "waiting": why }))
        }
        Err(why) => Err(why),
    }
}

/// ⭐ EARN — THIS WALLET'S POSITIONS: each one's units, what a withdrawal pays now at the pool's last tick (SAT and coin, at
/// the two roots: each at most the units' share), and the income its units have earned since they entered (at the pair's
/// public income index). Nothing here is read from anyone but this wallet's own node.
pub(crate) fn earn_positions_blocking() -> Result<serde_json::Value, String> {
    let f = read_defi();
    let mut rows = Vec::with_capacity(f.positions.len());
    for (i, p) in f.positions.iter().enumerate() {
        let pw = position_witness(p);
        let units = pw.units_max().unwrap_or(0);
        let book = post("/defi_book", serde_json::json!({ "pair": p.pair }), 10).ok();
        let tick = book.as_ref().and_then(|b| b["last_tick"].as_i64()).unwrap_or(p.tick);
        let index_now = book.as_ref().and_then(|b| b["income_index"].as_u64()).unwrap_or(pw.entry_index());
        let (sat, coin) = usdmd_node::defi_earn::withdraw_terms(units, tick).unwrap_or((0, 0));
        let income = (u128::from(units) * u128::from(index_now.saturating_sub(pw.entry_index()))) >> ba::INCOME_SHIFT;
        rows.push(serde_json::json!({
            "index": i,
            "coin": coin_name(p.pair),
            "units": units,
            "status": p.status,
            "deposited_sat": if p.from_withdrawal { serde_json::Value::Null } else { serde_json::json!(p.x as f64 / SAT_UNIT) },
            "withdraw_sat": sat as f64 / SAT_UNIT,
            "withdraw_coin": coin as f64 / coin_unit(p.pair),
            "income_sat": income as f64 / SAT_UNIT,
            "created_ms": p.created_ms,
        }));
    }
    Ok(serde_json::json!({ "positions": rows, "earn_every": usdmd_node::defi_earn::EARN_EVERY }))
}

/// ⭐ §18.14 SELL SAT: one sealed order of `sat` whole SAT for `coin`, the coin paid to `payout_to` on its own chain once the batch clears. The address is checked before anything is spent.
pub(crate) fn sell_sat_blocking(coin: String, sat: f64, payout_to: String) -> Result<serde_json::Value, String> {
    let pair = pair_of(&coin)?;
    let to = payout_to.trim().to_string();
    // Bitcoin with no address given: this wallet's own vault, a fresh address for every piece (the private default)
    let own_vault = pair == 0 && to.is_empty();
    let payable = if own_vault {
        crate::vault_address_at(0).is_ok()
    } else if pair == 0 {
        usdmd_node::btc_tx::script_pubkey_for_address(&to).is_some_and(|(net, _)| net == usdmd_node::bridge::btc_net())
    } else {
        usdmd_node::bridge::xmr_address_net(&to) == Some(usdmd_node::bridge::xmr_net_byte())
    };
    if !payable {
        return Err(if own_vault {
            "this wallet's Bitcoin vault needs its 24 words on this device (restore once more), or enter a Bitcoin address — nothing was spent".to_string()
        } else {
            format!("that is not a {} address on this network — nothing was spent", coin_name(pair))
        });
    }
    if pair == 0 && !own_vault {
        // Bitcoin is public: every piece paid to ONE outside address is one cluster worth the whole sale, which names the
        // deposit behind it (measured: 90 to 100 of 100 pieces). Auto-OPSEC refuses it; switched off, the user was warned.
        if crate::auto_opsec_on() {
            return Err(SWAP_OPSEC_REFUSES_ONE_ADDRESS.into());
        }
        crate::refuse_deposit_sender(&to)?;
    }
    let x = (sat * SAT_UNIT).round() as u64;
    if x == 0 {
        return Err("enter a positive amount — nothing was spent".into());
    }
    place_or_prepare(pair, true, Some(to), x, default_bucket())
}

/// What a sell to ONE outside Bitcoin address is told while Auto-OPSEC is on.
pub(crate) const SWAP_OPSEC_REFUSES_ONE_ADDRESS: &str = "Auto-OPSEC is on: Bitcoin is a public chain, and every piece of this sale paid to one address \
     would add up to the sale and point back at your deposit. Leave the address empty to receive in this wallet's own Bitcoin vault \
     (a fresh address for every piece), or switch Auto-OPSEC off in Settings if you do not need this sale to be private — nothing was spent";

/// ⭐ BUY SAT WITH BITCOIN, PRIVATELY (Auto-OPSEC on, the default): the private deposit plan first (§BR-6's entry mix), each mixed deposit minting a Bitcoin note, then one sealed order per note, placed on its own
/// (`sat_buy_mix_tick`) the moment the last mixed deposit mints.
pub(crate) fn buy_sat_private_btc_blocking(max_bucket: usize) -> Result<serde_json::Value, String> {
    if max_bucket >= ba::ORDER_BUCKETS {
        return Err("that maximum price is not one of the choices".into());
    }
    crate::mix_client::sat_buy_mix_start(max_bucket)
}

/// The private Bitcoin buys whose deposits have all minted: each note becomes its own order — whatever screen is open (the wallet's background tick and the trade poll both run it).
pub(crate) fn sat_buy_mix_tick() {
    for (plan, notes, bucket) in crate::mix_client::sat_buy_mix_ready() {
        let mut f = read_defi();
        for atomic in &notes {
            f.exact.push(ExactOrder { pair: 0, sell: false, payout: None, amount: *atomic, bucket, created_ms: now_ms(), prepared: true, deposit: false });
        }
        let done = write_defi(&f);
        crate::mix_client::sat_buy_mix_note(
            &plan,
            match done {
                Ok(()) => "Your private deposit minted · your SAT orders are sent and fill in the next batch".to_string(),
                Err(e) => format!("Your private deposit minted, but the SAT order could not start ({e}) — your Bitcoin note is safe in this wallet"),
            },
        );
    }
}

/// The outcome of `o`'s batch: `Some(Some((tick, j_min, sells)))` settled, `Some(None)` expired, `None` not yet known.
fn outcome_of(o: &DefiOrder, book: &serde_json::Value, out_sk: &[u8; 32]) -> Option<Option<(i64, u64, bool)>> {
    outcome_x_of(o, book, out_sk).map(|x| x.0)
}

/// ⭐ EARN — the outcome with the leaf's own lanes: `(outcome, earn, dep)` — an Earn leaf, and the deposit batch's lane (the
/// batch counted deposits and its sells cleared). A refund leaf carries neither.
fn outcome_x_of(o: &DefiOrder, book: &serde_json::Value, out_sk: &[u8; 32]) -> Option<(Option<(i64, u64, bool)>, bool, bool)> {
    let batch = book["batch"].as_u64()?;
    if o.batch == u64::MAX {
        return None;
    }
    if batch <= o.batch {
        return None;
    }
    if batch == o.batch + 1 && book["last_expired"].as_bool() == Some(true) {
        return Some((None, false, false));
    }
    // the node finds the order's leaf among the notes it holds — at the batch's known tick (the last one, when this is the
    // batch just closed), else across the range (a batch this wallet missed); the leaf names the lowest bucket that filled
    let hint = (batch == o.batch + 1).then(|| book["last_tick"].as_i64()).flatten();
    let blind = amount_blind_for(out_sk, o.nonce);
    let ac = ba::amount_commit(o.amount, &blind);
    let lc = order_limit_commit(o, &blind);
    let hx = |d: &[u64; 8]| hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(d));
    let mut req = serde_json::json!({ "amount_commit_hex": hx(&ac), "limit_commit_hex": hx(&lc), "pair": o.pair });
    if let Some(t) = hint {
        req["tick"] = serde_json::Value::String(t.to_string());
    }
    let r = post("/defi_fill", req, 30).ok()?;
    let (earn, dep) = (r["earn"].as_bool().unwrap_or(false), r["dep"].as_bool().unwrap_or(false));
    match (r["status"].as_str(), r["refund"].as_bool()) {
        (Some("OK"), Some(true)) => Some((None, false, false)),
        (Some("OK"), Some(false)) => Some((Some((r["tick"].as_i64()?, r["j_min"].as_u64()?, r["sells"].as_bool()?)), earn, dep)),
        _ => None,
    }
}

/// ⭐ THE CLAIM of a known outcome: the claim relation's proof, the claim leaf's member leg at the node's newest root (NOT_YET
/// only until the leaf's record folds — one fold step — `Ok(None)`), the minted note sealed to this wallet under a reserved index: SAT for a buyer's fill or a seller's returned SAT, the coin for a seller's fill or a buyer's money back.
/// ⭐ A-F25 (2026-11-11): EPOCH ANCHOR ONLY. The node's `/defi_claim_member_leg` answers ONLY at an epoch anchor (~26 h kept).
/// `None` until the next anchor (≤ 10 min of chain time) holds the note. MEASURED: a ring-root leg (64 steps, ~13 min) aged
/// out while an order waited 25–40 min for its batch; the fold refused it on a peer. BORROWED: Zcash wallets' anchor depth.
fn defi_slot_leg(_agent: &ureq::Agent, cm: &[u8; 32], nf: Digest4, blind: Digest4) -> Option<(String, String)> {
    // ⭐ A-F25 (2026-11-11): EPOCH ANCHOR ONLY — the ring-root path (`membership_bind_for`) is removed. A DeFi
    // object's leg must survive until its batch settles (25–40 min at the real block rate); the ring (64 steps,
    // ~13 min) ages out and the fold refuses it on a peer. The node's `/defi_claim_member_leg` now answers ONLY
    // at an epoch anchor (kept ~26 h). NOT_YET (None here) until the next anchor holds the note (≤ 10 min).
    let leg = post(
        "/defi_claim_member_leg",
        serde_json::json!({
            "cm_hex": hex::encode(cm),
            "claim_nullifier": hex::encode(leaf4_to_bytes(nf)),
            "blind_hex": hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(&blind)),
        }),
        60,
    )
    .ok();
    let field = |k: &str| leg.as_ref().and_then(|l| l[k].as_str().map(str::to_string));
    match (field("membership_carrier_hex"), field("membership_tip_hex")) {
        (Some(m), Some(t)) => Some((m, t)),
        _ => None,
    }
}

/// ⭐ EARN — the leaf an order's batch inserted for it, by its outcome and lanes: the prices, the lowest filling bucket and
/// the lanes (`defi_batch::settle_leaves`' own spelling: a refund leaf, an Earn leaf at the two withdrawal rates, or a trading
/// leaf at the tick).
fn leaf_terms(o: &DefiOrder, outcome: Option<(i64, u64, bool)>) -> (u128, u128, u64, u128, u128, ba::LeafExtra) {
    let x = ba::LeafExtra { earn: o.earn && outcome.is_some(), dep: o.dep && outcome.is_some() };
    match outcome {
        None => (1, 1, ba::ORDER_BUCKETS as u64, 0, 1, x),
        Some((t, _, _)) if x.earn => {
            let ((pn, pd), (sn, sd)) = db::earn_rates(t);
            (pn, pd, ba::ORDER_BUCKETS as u64, sn, sd, x)
        }
        Some((t, j, sells)) => {
            let (n1, d1) = usdmd_node::defi_clear::tick_ratio(t + 1);
            let (sn, sd) = db::sell_price(t, sells);
            (d1, n1, j, sn, sd, x)
        }
    }
}

fn claim_order(o: &DefiOrder, outcome: Option<(i64, u64, bool)>) -> Result<Option<(String, String)>, String> {
    claim_order_leg(o, outcome, 0)
}

/// One claim of an order: `leg` 0 for every order (a withdrawal's SAT and income), 1 for a withdrawal's coin.
fn claim_order_leg(o: &DefiOrder, outcome: Option<(i64, u64, bool)>, leg: u8) -> Result<Option<(String, String)>, String> {
    let (my_ek, loc_sk, out_sk, keys) = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.scan_ek.clone(), w.loc_sk, w.out_sk, w.note_keys())
    };
    let a_blind = amount_blind_for(&out_sk, o.nonce);
    let (p_num, p_den, j_min, s_num, s_den, extra) = leaf_terms(o, outcome);
    let withdraw = o.kind == "withdraw";
    // ⭐ EARN STEP 3 — the order's two indices, as its limit commitment names them: a deposit's entry is its batch's opening
    // index; a withdrawal's entry is its position's, its "now" its batch's opening index; a trade's are zero
    let (entry, now) = match (o.kind.as_str(), &o.position) {
        ("deposit", _) => (o.index, 0),
        ("withdraw", Some(p)) => (position_witness(p).entry_index(), o.index),
        _ => (0, 0),
    };
    let mut cw = ba::ClaimWitness {
        cover: None,
        amount: o.amount,
        amount_blind: a_blind,
        bucket: o.bucket as u64,
        sell: o.sell && !withdraw,
        deposit: o.kind == "deposit",
        withdraw,
        leg,
        extra,
        entry,
        now,
        p_num,
        p_den,
        j_min,
        s_num,
        s_den,
        out: 0,
        out_blind: wr::fresh_lc_blind().ok_or("no entropy for the claim")?,
        lc_blind: wr::fresh_lc_blind().ok_or("no entropy for the claim")?,
    };
    // what the claim relation pays at this leaf, by its own native rule
    cw.out = cw.paid().ok_or("the fill does not fit")?;
    let out = cw.out;
    let (nf, lc, oc, pays_y) = cw.publics();
    let leaf = cw.leaf();
    let leg = post(
        "/defi_claim_member_leg",
        serde_json::json!({
            "cm_hex": hex::encode(leaf4_to_bytes(leaf)),
            "claim_nullifier": hex::encode(leaf4_to_bytes(nf)),
            "blind_hex": hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(&cw.lc_blind)),
        }),
        60,
    )?;
    let field = |k: &str| leg[k].as_str().map(str::to_string);
    let (Some(mem), Some(tip)) = (field("membership_carrier_hex"), field("membership_tip_hex")) else {
        // DIGITAL-CASH-PRIVACY-REVIEWED: the node's fixed reason string, to this wallet's own log.
        eprintln!("[defi] a claim's member leg is not ready yet: {}", leg["why"].as_str().unwrap_or("no reason given"));
        return Ok(None);
    };
    if field("leaf_commit_hex").as_deref() != Some(hex::encode(leaf4_to_bytes(lc)).as_str()) {
        return Err("the claim leaf's member leg does not bind this claim".into());
    }
    let claim_proof = usdmd_node::defi_custody::claim_proof(&cw).ok_or("the claim did not prove")?;
    let nf_bytes = leaf4_to_bytes(nf);
    let asset = if pays_y { db::pair_y_tag(o.pair) } else { usdmd_node::satoshi::asset_tag() };
    let reservation = reserve_chg_indices(1, &[nf_bytes])?;
    let j = reservation.indices.first().copied().ok_or("no index reserved")?;
    let (note, opening) = pq::seal_self_note_with_record(&my_ek, &keys.spk, out, asset, &out_sk, &nf_bytes, &chg_domain(), j).ok_or("could not seal the claimed note")?;
    let (mint, cm, dc) = wr::prove_asset_mint_validity_committed_bytes(out, asset, &opening, &cw.out_blind).ok_or("the claimed note's mint did not prove")?;
    if dc != oc || note[..32] != leaf4_to_bytes(cm)[..] {
        return Err("refusing: the minted note is not the claim's".into());
    }
    let recs = self_note_clue_records(&loc_sk, &[leaf4_to_bytes(cm)], &[Some(j)]);
    let owner_clue = recs.get(34..).filter(|c| !c.is_empty()).map(<[u8]>::to_vec).ok_or("the claimed note's clue could not be derived")?;
    let claim = db::DefiClaimTx {
        pair: o.pair,
        nullifier: nf,
        leaf_commit: lc,
        out_commit: oc,
        pays_y,
        claim_proof,
        member_carrier: hex::decode(&mem).map_err(|e| format!("member leg hex: {e}"))?,
        member_tuple: hex::decode(&tip).map_err(|e| format!("member tip hex: {e}"))?,
        mint_carrier: mint,
        note: note.to_vec(),
        owner_clue,
    };
    if let Some(why) = claim.self_valid() {
        return Err(format!("refusing: the claim does not verify ({why})"));
    }
    let bytes = hex::encode(claim.encode().ok_or("the claim did not encode")?);
    let r = post("/submit_defi_claim", serde_json::json!({ "object_hex": bytes.clone() }), 30)?;
    if r["verdict"].as_str() != Some("HANDED_TO_CUSTODY") {
        return Err(format!("the node refused the claim: {}", r["reason"].as_str().unwrap_or("no reason named")));
    }
    reservation.commit(nf_bytes);
    Ok(Some((hex::encode(&claim.note[..32]), bytes)))
}

/// ⭐ §18.14 ONE RUNG OF A SELL'S PAYOUT: the committed burn of `rung` atoms from the smallest coin note that covers it, naming `to` under its ticket, sealed to the key custody already holds (§18.14), change back to this wallet.
/// `Ok(Some(nullifier))` the node holds the burn; `Ok(None)` not yet (no spendable note, or its member leg or the key is not ready). Nothing moves until the burn folds.
fn burn_coin_rung(pair: u8, to: &str, rung: u64, pay_after: u64) -> Result<Option<String>, String> {
    // CHAIN-OBJECT: the `Class::PegOut` object this builds and posts to the node's pool. The coin note is spent when a block
    // carries that object and every node applies it at the fold; this wallet only builds it and records what the node said.
    if slot_status() != note_store::SlotStatus::Decided {
        return Ok(None);
    }
    let tag = db::pair_y_tag(pair);
    let (my_ek, loc_sk, keys) = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        let w = g.as_ref().ok_or_else(|| "no wallet open".to_string())?;
        (w.scan_ek.clone(), w.loc_sk, w.note_keys())
    };
    let note = {
        let held = PROVEN_SPENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let s = SCAN.lock().unwrap_or_else(|e| e.into_inner());
        s.as_ref().and_then(|st| {
            st.owned
                .iter()
                .filter(|n| n.asset == tag && n.amount >= rung && spendable_now(&st.spent, &st.pending_change, &held, n.amount, n.seed, &n.nf))
                .min_by_key(|n| n.amount)
                .map(|n| (n.amount, n.seed))
        })
    };
    let Some((value_in, in_seed)) = note else { return Ok(None) };
    let in_owner = keys.owner(in_seed);
    let nullifier = pq_spend::note_nullifier_asset(value_in, &in_owner, tag);
    let change = value_in - rung;
    let (change_note, change_opening) = pq::seal_note_full_asset(&my_ek, &keys.spk, change, tag).ok_or("the burn's change could not be sealed — nothing was built")?;
    let change_cm: [u8; 32] = change_note.get(..32).and_then(|c| <[u8; 32]>::try_from(c).ok()).ok_or("the change note has no commitment")?;
    let ((_dom, j), _no_self, reservation) = dense_locators_for(false, &[nullifier])?;
    let recs = self_note_clue_records(&loc_sk, &[change_cm], &[Some(j)]);
    let clue = recs.get(34..).filter(|c| !c.is_empty()).map(<[u8]>::to_vec).ok_or("the change clue could not be derived")?;
    let (ticketed, parts_hex, leg_blind) = match ticket_for(&nullifier, to, pay_after, rung, &clue, true) {
        Ok(t) => t,
        Err(why) if why.contains("custody key") => return Ok(None),
        Err(why) => return Err(why),
    };
    let lc_blind = wr::fresh_lc_blind().ok_or("no entropy for the cross-bind blind — nothing was built")?;
    let w = wr::AssetSpendValidityWitness {
        value_in,
        owner: in_owner,
        value_out: value_in,
        fee: 0,
        lc_blind,
        out0_value: rung,
        out0_opening: usdmd_node::cashout_ticket::burn_out_opening(&ticketed, &leg_blind),
        out1_value: change,
        out1_opening: change_opening,
        asset: tag,
    };
    let (carrier, cms, nf, leaf_commit, burn_commit) = wr::prove_asset_burn_committed_bytes(&w, &usdmd_node::peg::peg_out_burn_blind(&leg_blind)).ok_or("the burn did not prove — nothing was built")?;
    if burn_commit != usdmd_node::peg::peg_out_burn_commit(u128::from(rung), &leg_blind)
        || !wr::verify_asset_burn_committed_bytes(&carrier, cms[0], cms[1], nf, leaf_commit, burn_commit, tag)
        || leaf4_to_bytes(nf) != nullifier
        || leaf4_to_bytes(cms[1]) != change_cm
        || cms[0] != usdmd_node::cashout_ticket::burn_out_cm_of(coin_ledger(pair), rung, &ticketed, &leg_blind)
    {
        return Err("the burn did not verify against its own binding — nothing was relayed".into());
    }
    let cm_in = leaf4_to_bytes(wr::asset_note_cm(value_in, tag, in_owner.opening()));
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let Some((mem, tip)) = membership_bind_for(&agent, &cm_in, nf, lc_blind) else { return Ok(None) };
    let r = post(
        "/peg_out_execute",
        serde_json::json!({
            "coin": 1,
            "usdm_nullifier": hex::encode(nullifier),
            "out0_cm": hex::encode(leaf4_to_bytes(cms[0])),
            "out1_cm": hex::encode(change_cm),
            "burn_carrier_hex": hex::encode(&carrier),
            "burn_amount": rung,
            "change_note_payload": hex::encode(change_note),
            "redeem_to": to,
            "pay_after": pay_after,
            "membership_carrier_hex": mem,
            "membership_tip_hex": tip,
            "membership_leaf_commit": hex::encode(leaf4_to_bytes(leaf_commit)),
            "note_clue_hex": hex::encode(&clue),
            "ticketed_commit": hex::encode(ticketed),
            "ticket_parts_hex": parts_hex,
            "leg_blind_hex": hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(&leg_blind)),
        }),
        60,
    )?;
    let held = ["redeemed", "published", "gathering"].iter().any(|k| r[*k].as_bool() == Some(true));
    if !held {
        return Err(format!("the node refused the burn: {}", r["outcome"].as_str().unwrap_or("no reason named")));
    }
    reservation.commit(nullifier);
    Ok(Some(hex::encode(nullifier)))
}

/// ⭐ §18.14 — each sell's payout, one rung per note at a time: a burn in flight ends when its note is spent on the chain (the next rung takes its change), or is built again if this wallet's node forgot it. What is below the coin's smallest rung stays a coin note here.
fn advance_payouts(f: &mut DefiFile) {
    let chain_now = crate::node_chain_time_ms();
    // the vault's one index line, counted through this pass (two payouts in one pass never draw one index)
    let mut next_vault = crate::vault_next_index(&crate::read_cashouts())
        .max(f.vault_rungs.iter().map(|v| v.index + 1).max().unwrap_or(0))
        .max(f.payouts.iter().filter_map(|p| p.next_vault).map(|i| i + 1).max().unwrap_or(0));
    // every later moment a piece of this wallet already waits for, as offsets after now: its cash-out pieces and its sells' rungs
    let mut taken: Vec<u64> = crate::read_cashouts()
        .iter()
        .flat_map(|p| p.pieces.iter())
        .filter(|c| c.status == "pending" && c.pay_after > chain_now)
        .map(|c| c.pay_after - chain_now)
        .chain(f.payouts.iter().flat_map(|p| p.handed_after.iter().copied().chain(std::iter::once(p.next_pay_after))).filter(|t| *t > chain_now).map(|t| t - chain_now))
        .collect();
    let mut paid_to_vault: Vec<VaultRung> = Vec::new();
    for p in &mut f.payouts {
        p.handed_after.retain(|t| *t > chain_now);
        if let Some((nf_hex, rung)) = p.burning.clone() {
            if piece_burned(&nf_hex) == Some(true) {
                p.left = p.left.saturating_sub(rung);
                p.sent = p.sent.saturating_add(rung);
                p.burning = None;
                // that rung is custody's to pay now: its address is this wallet's coin for good, its slot stays taken
                if let (Some(index), Some(address)) = (p.next_vault, p.next_to.clone()) {
                    paid_to_vault.push(VaultRung { index, address, amount: rung, pay_after: p.next_pay_after, created_ms: now_ms() });
                }
                if p.next_pay_after > chain_now {
                    p.handed_after.push(p.next_pay_after);
                }
                (p.next_to, p.next_pay_after, p.next_vault) = (None, 0, None);
            } else if claim_held(&nf_hex) == Some(false) {
                p.burning = None; // built again below, to the SAME address and delay
            } else {
                continue;
            }
        }
        let ledger = coin_ledger(p.pair);
        let Some(rung) = usdmd_node::peg_pool::split_to_coin_denoms(ledger, p.left).0.first().copied() else { continue };
        // where this rung pays and when, drawn once
        if p.next_to.is_none() {
            match rung_route(p.pair, &p.to, p.opsec, chain_now, &taken, next_vault) {
                Ok(Some((to, pay_after, vault))) => {
                    if vault.is_some() {
                        next_vault += 1;
                    }
                    if pay_after > chain_now {
                        taken.push(pay_after - chain_now);
                    }
                    (p.next_to, p.next_pay_after, p.next_vault) = (Some(to), pay_after, vault);
                }
                Ok(None) => continue, // the chain's clock is not known yet: a paced rung is never sent without its delay
                Err(why) => {
                    eprintln!("[defi] a payout rung has no destination yet: {why}");
                    continue;
                }
            }
        }
        let Some(to) = p.next_to.clone() else { continue };
        // CHAIN-OBJECT: the rung leaves as a `Class::PegOut` object a block carries (`burn_coin_rung`); `p.burning` below is
        // CACHE-ONLY, this wallet's note of what it posted, cleared when the chain shows the object folded.
        match burn_coin_rung(p.pair, &to, rung, p.next_pay_after) {
            Ok(Some(nf)) => p.burning = Some((nf, rung)),
            Ok(None) => {}
            Err(why) => eprintln!("[defi] a payout rung was not taken yet: {why}"),
        }
    }
    f.vault_rungs.extend(paid_to_vault);
    let smallest = |pair: u8| usdmd_node::peg_pool::coin_denoms(coin_ledger(pair)).first().copied().unwrap_or(u64::MAX);
    f.payouts.retain(|p| p.burning.is_some() || p.left >= smallest(p.pair));
}

/// ⭐ WHERE ONE RUNG OF A SELL PAYS, AND WHEN (Auto-OPSEC, user 2026-11-10). `to` empty = this wallet's own Bitcoin vault: a
/// fresh address at `next_vault` for this rung alone. With Auto-OPSEC on, the rung's pay-after is its own later payout
/// slot, drawn the way a cash-out piece's is (`distinct_pay_after_slots`: uniform inside the lane's window, never a slot
/// another piece of this wallet waits in); `Ok(None)` while the chain's clock is unknown (a paced rung is never sent
/// without its delay). With it off: at once. Returns `(address, pay-after in chain ms, vault index)`.
fn rung_route(pair: u8, to: &str, opsec: bool, chain_now: u64, taken: &[u64], next_vault: u32) -> Result<Option<(String, u64, Option<u32>)>, String> {
    let (address, vault) = if pair == 0 && to.is_empty() { (crate::vault_address_at(next_vault)?, Some(next_vault)) } else { (to.to_string(), None) };
    if !opsec {
        return Ok(Some((address, 0, vault)));
    }
    if chain_now == 0 {
        return Ok(None);
    }
    let delay = crate::distinct_pay_after_slots(1, taken, false, &mut rand::rngs::OsRng)
        .pop()
        .unwrap_or(usdmd_node::btc_payout::PROPOSER_SLOT_MS);
    Ok(Some((address, chain_now + delay, vault)))
}

/// ⭐ PROGRESS: place the orders whose deposits minted, learn each open order's outcome, claim each known one, start each sell's payout (a claimed order's row leaves the list: its note is now owned).
/// Returns the orders in flight, the claims made now, the deposits still waiting and the payouts on their way.
pub(crate) fn defi_progress_blocking() -> Result<serde_json::Value, String> {
    sat_buy_mix_tick();
    let mut f = read_defi();
    // the deposits that minted: their notes are exactly their amounts, so their orders are placed from here
    let mut i = 0;
    while i < f.intents.len() {
        if f.intents[i].status != "waiting" {
            i += 1;
            continue;
        }
        // the honest auto-mint runs here too, so a buy finishes on its own whatever screen is open
        let _ = wallet_try_mint_blocking(f.intents[i].swap_id.clone());
        let minted = wallet_swap_status_blocking(f.intents[i].swap_id.clone()).ok().and_then(|r| r["status"].as_str().map(|s| s == "minted")) == Some(true);
        if !minted {
            i += 1;
            continue;
        }
        let it = f.intents.remove(i);
        f.exact.push(ExactOrder { pair: it.pair, sell: false, payout: None, amount: it.amount, bucket: it.bucket, created_ms: it.created_ms, prepared: true, deposit: false });
    }
    // ⭐ EARN — the positions waiting to be withdrawn: each placed the moment its pair's Earn batch takes orders
    let waiting_w: Vec<PositionRec> = f.positions.iter().filter(|p| p.status == "withdrawing").cloned().collect();
    for rec in waiting_w {
        match place_withdrawal(&rec) {
            Ok(_) => {
                f.positions.retain(|q| q != &rec);
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line; no units, position or key.
                eprintln!("[earn] a withdrawal was handed to custody for the Earn batch");
            }
            Err(why) if why.contains("waits for the pool's Earn batch") => {}
            Err(why) => eprintln!("[earn] a withdrawal was not placed yet: {why}"),
        }
    }
    // the orders waiting for their exact-amount note: placed the moment it is owned; nothing here ever fails for good, the note stays this wallet's
    let waiting = std::mem::take(&mut f.exact);
    write_defi(&f)?;
    let mut still = Vec::new();
    for mut e in waiting {
        match place_order_kind(e.pair, e.sell, e.payout.clone(), e.amount, e.bucket, e.deposit) {
            Ok(_) => {}
            Err(why) => {
                if why != NEED_EXACT {
                    eprintln!("[defi] a prepared order was not taken yet: {why}");
                } else if e.prepared {
                    // A prepared order whose exact note is still not usable waited here with no line for a whole run (MEASURED
                    // 2026-11-08, launch_trade.py: "preparing" for 30 minutes after its self-payment was published). Say which half
                    // is missing: the note, or its spendability. DIGITAL-CASH-PRIVACY-REVIEWED: counts of this wallet's own notes to
                    // its own log; no amount, commitment or key.
                    let tag = spend_tag(e.pair, e.sell);
                    let held = PROVEN_SPENT.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    let (of_asset, exact, usable) = SCAN
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .as_ref()
                        .map(|st| {
                            let of: Vec<&OwnedNote> = st.owned.iter().filter(|n| n.asset == tag).collect();
                            let ex: Vec<&&OwnedNote> = of.iter().filter(|n| n.amount == e.amount).collect();
                            let us = ex.iter().filter(|n| spendable_now(&st.spent, &st.pending_change, &held, n.amount, n.seed, &n.nf)).count();
                            (of.len(), ex.len(), us)
                        })
                        .unwrap_or((0, 0, 0));
                    eprintln!("[defi] a prepared order waits for its exact note: {of_asset} note(s) of its asset, {exact} of its exact amount, {usable} spendable now");
                } else if !e.prepared {
                    let made = wallet_address().ok().and_then(|a| a["address"].as_str().map(str::to_string)).map(|me| wallet_send_asset_atomic_blocking(&me, spend_tag(e.pair, e.sell), e.amount, if e.sell { "SAT" } else { coin_name(e.pair) }));
                    e.prepared = matches!(made, Some(Ok(_)));
                }
                still.push(e);
            }
        }
    }
    f = read_defi();
    f.exact.extend(still);
    write_defi(&f)?;
    let mut books = Vec::new();
    for pair in 0..db::PAIRS {
        books.push(post("/defi_book", serde_json::json!({ "pair": pair }), 10)?);
    }
    let out_sk = {
        let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().ok_or_else(|| "no wallet open".to_string())?.out_sk
    };
    let mut claimed = Vec::new();
    let mut in_flight = Vec::with_capacity(f.orders.len());
    for mut o in std::mem::take(&mut f.orders) {
        let book = &books[usize::from(o.pair)];
        if o.batch == u64::MAX {
            // an order learns its batch when the book's slots carry its amount commitment
            let ac = hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(&ba::amount_commit(o.amount, &amount_blind_for(&out_sk, o.nonce))));
            if book["order_commits_hex"].as_array().is_some_and(|a| a.iter().any(|v| v.as_str() == Some(ac.as_str()))) {
                o.batch = book["batch"].as_u64().unwrap_or(0);
            } else if o.status == "open"
                && book["batch"].as_u64().is_some_and(|b| b > o.sent_batch)
                // ⭐ EARN STEP 3 — a copy dealt again at ANOTHER index names another limit commitment, so it goes only once the
                // batch after the one that passed it has opened: a copy that did land at the old index has folded its leaf by
                // then, and the leaf check below finds it
                && (book["batch_index"].as_u64() == Some(o.index) || o.kind.is_empty() || book["batch"].as_u64().is_some_and(|b| b > o.sent_batch + 1))
            {
                // ⭐ A BATCH PASSED THIS ORDER BY. Custody may have lost it, or its member leg aged out; either way nothing here tells this wallet, so it never waits on silence. If the order landed and this wallet missed its window, its leaf says so; otherwise it goes again.
                let ba_blind = amount_blind_for(&out_sk, o.nonce);
                let hx = |d: &[u64; 8]| hex::encode(usdmd_node::spend_frontier::digest_to_lane_bytes(d));
                let req = serde_json::json!({
                    "amount_commit_hex": hx(&ba::amount_commit(o.amount, &ba_blind)),
                    "limit_commit_hex": hx(&order_limit_commit(&o, &ba_blind)),
                });
                if post("/defi_fill", req, 30).ok().and_then(|r| r["status"].as_str().map(|s| s == "OK")) == Some(true) {
                    o.batch = book["batch"].as_u64().unwrap_or(1).saturating_sub(1);
                } else if let (true, Some(p)) = (o.kind == "withdraw", o.position.clone()) {
                    // ⭐ EARN — a withdrawal a batch passed by goes again under its own nonce (the same position nullifier: only
                    // one copy spends the position), at the next Earn batch's opening index
                    match place_withdrawal_at(&p, Some(o.nonce)) {
                        Ok(sent) => {
                            o.sent_batch = sent.sent_batch;
                            o.index = sent.index;
                            eprintln!("[earn] a batch passed a withdrawal by: it was sent again");
                        }
                        Err(why) => eprintln!("[earn] a withdrawal a batch passed by was not sent again yet: {why}"),
                    }
                } else if let Some(nf) = o.input_nf.as_deref().and_then(|h| hex::decode(h).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                    match deal_order(o.pair, o.sell, o.payout.clone(), o.amount, o.bucket, Some((o.nonce, nf)), o.kind == "deposit") {
                        Ok(sent) => {
                            o.sent_batch = sent.sent_batch;
                            // the copy carries the open batch's index (its limit commitment names it: a deposit's entry)
                            o.index = sent.index;
                            eprintln!("[defi] a batch passed an order by: it was sent again");
                        }
                        Err(why) => eprintln!("[defi] an order a batch passed by was not sent again yet: {why}"),
                    }
                }
            }
        }
        // a claim handed to custody: done once its note is owned, resent if a batch's slots passed it by
        if let (Some(cm), Some(bytes)) = (o.claim_cm.clone(), o.claim_hex.clone()) {
            let mine: Vec<&str> = std::iter::once(cm.as_str()).chain(o.claim_prev.iter().map(String::as_str)).collect();
            let owned = SCAN.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|st| st.owned.iter().any(|n| n.note.get(..32).map(hex::encode).is_some_and(|c| mine.contains(&c.as_str()))));
            // ⭐ EARN — a withdrawal is done once BOTH its claims' notes are owned; its coin claim is built (or resent) here
            if owned && o.kind == "withdraw" {
                let leg1_owned = o.claim2_cm.as_deref().is_some_and(|c2| {
                    SCAN.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|st| st.owned.iter().any(|n| n.note.get(..32).map(hex::encode).as_deref() == Some(c2)))
                });
                if !leg1_owned {
                    match (o.claim2_hex.clone(), o.tick.map(|tk| (tk, o.j_min, o.sells))) {
                        (Some(b2), _) if now_ms().saturating_sub(o.claim_sent_ms) > 30_000 => {
                            let _ = post("/submit_defi_claim", serde_json::json!({ "object_hex": b2 }), 30);
                            o.claim_sent_ms = now_ms();
                        }
                        (None, outcome2) => {
                            if let Ok(Some((cm2, b2))) = claim_order_leg(&o, outcome2, 1) {
                                o.claim2_cm = Some(cm2);
                                o.claim2_hex = Some(b2);
                            }
                        }
                        _ => {}
                    }
                    in_flight.push(o);
                    continue;
                }
            }
            if owned {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line and the public batch number; no note, amount or key.
                eprintln!("[defi] a claim landed: its note is this wallet's (built at batch {})", o.claim_batch);
                claimed.push(serde_json::json!({ "coin": coin_name(o.pair), "sell": o.sell, "status": o.status, "paid": o.amount, "got": o.out, "got_coin": o.out as f64 / if pays_coin(&o) { coin_unit(o.pair) } else { SAT_UNIT }, "pays_coin": pays_coin(&o), "kind": if o.kind.is_empty() { "trade" } else { o.kind.as_str() } }));
                if let (true, "filled", Some(to)) = (o.sell, o.status.as_str(), o.payout.clone()) {
                    f.payouts.push(CoinPayout {
                        pair: o.pair,
                        to,
                        left: o.out,
                        sent: 0,
                        burning: None,
                        created_ms: now_ms(),
                        opsec: crate::auto_opsec_on(),
                        next_to: None,
                        next_pay_after: 0,
                        next_vault: None,
                        handed_after: Vec::new(),
                    });
                }
                continue;
            }
            // ⭐ TWO BATCHES PASSED THIS CLAIM BY: its member leg is anchored to the ring root of when it was built, and a claim
            // waits in custody for a batch's slots, so a leg older than the ring is a slot custody drops as dead ("can never
            // be carried") — and re-sending the same bytes could never land. MEASURED 2026-11-09 (launch_trade.py, real nodes):
            // the launch account's returned sell waited over an hour for its refund while batches ran 15–25 min apart. Built
            // again with a fresh leg, as an order a batch passed by goes again; the old copy stays counted if it lands.
            if book["batch"].as_u64().is_some_and(|b| b >= o.claim_batch.saturating_add(2)) {
                eprintln!("[defi] a claim two batches passed by is built again with a fresh member leg");
                o.claim_prev.push(cm);
                o.claim_cm = None;
                o.claim_hex = None;
            } else {
                if now_ms().saturating_sub(o.claim_sent_ms) > 30_000 {
                    let _ = post("/submit_defi_claim", serde_json::json!({ "object_hex": bytes }), 30);
                    o.claim_sent_ms = now_ms();
                }
                in_flight.push(o);
                continue;
            }
        }
        let outcome = if o.status == "open" {
            match outcome_x_of(&o, book, &out_sk) {
                Some((t, earn, dep)) => {
                    o.tick = t.map(|(tk, _, _)| tk);
                    o.j_min = t.map_or(ba::ORDER_BUCKETS as u64, |(_, j, _)| j);
                    o.sells = t.is_some_and(|(_, _, s)| s);
                    o.earn = earn;
                    o.dep = dep;
                    // ⭐ EARN — a deposit that COUNTED is a position (its claim would mint 0: nothing to claim): its leaf's
                    // deposit lane is set (a deposit batch whose sells cleared). One that did not (an expired batch, the sells
                    // off, a batch that was no deposit batch) is refunded whole by its claim
                    if o.kind == "deposit" {
                        if let (Some((tk, j, true)), false, true) = (t, earn, dep) {
                            f.positions.push(PositionRec {
                                pair: o.pair,
                                x: o.amount,
                                nonce: o.nonce,
                                bucket: o.bucket as u64,
                                from_withdrawal: false,
                                entry: o.index,
                                tick: tk,
                                j_min: j,
                                sells: true,
                                now: 0,
                                dep: true,
                                status: "open".into(),
                                created_ms: now_ms(),
                            });
                            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line; no amount, position or key.
                            eprintln!("[earn] a deposit counted: it is a position of this wallet's");
                            continue;
                        }
                        o.status = "returned".into();
                        o.out = o.amount;
                    }
                    // ⭐ EARN — a withdrawal at an Earn leaf is paid (two claims); anywhere else its units ROLL into a position
                    // of its own leaf, withdrawn again at the next Earn batch
                    if o.kind == "withdraw" {
                        if !earn {
                            let entry = o.position.as_ref().map_or(0, |p| position_witness(p).entry_index());
                            let (tk, j, s) = t.unwrap_or((0, ba::ORDER_BUCKETS as u64, false));
                            // its own leaf names its entry (the withdrawn position's) and its "now" (its batch's opening index)
                            f.positions.push(PositionRec {
                                pair: o.pair,
                                x: o.amount,
                                nonce: o.nonce,
                                bucket: o.bucket as u64,
                                from_withdrawal: true,
                                entry,
                                tick: tk,
                                j_min: j,
                                sells: s,
                                now: o.index,
                                dep,
                                status: "withdrawing".into(),
                                created_ms: now_ms(),
                            });
                            eprintln!("[earn] a withdrawal met no Earn batch: its units roll on and go again at the next one");
                            continue;
                        }
                        o.status = "withdrawn".into();
                    }
                    if o.kind.is_empty() {
                        o.out = usdmd_node::defi_custody::claim_terms(o.amount, o.bucket, o.sell, t).map_or(0, |v| v.5);
                        o.status = match (t, o.sell) {
                            (Some((_, _, true)), true) => "filled".into(),
                            (_, true) => "returned".into(),
                            (Some((_, j, _)), false) if o.bucket as u64 >= j => "filled".into(),
                            (Some(_), false) => "above_max".into(),
                            (None, false) => "refunded".into(),
                        };
                    }
                    t
                }
                None => {
                    in_flight.push(o);
                    continue;
                }
            }
        } else {
            o.tick.map(|tk| (tk, o.j_min, o.sells))
        };
        // ⭐ EARN — a paid withdrawal's second claim, its coin leg, built beside its first
        if o.kind == "withdraw" && o.claim2_cm.is_none() {
            match claim_order_leg(&o, outcome, 1) {
                Ok(Some((cm2, b2))) => {
                    o.claim2_cm = Some(cm2);
                    o.claim2_hex = Some(b2);
                }
                Ok(None) => {}
                Err(why) => eprintln!("[earn] a withdrawal's coin claim was not taken yet: {why}"),
            }
        }
        match claim_order(&o, outcome) {
            Ok(Some((cm, bytes))) => {
                o.claim_cm = Some(cm);
                o.claim_hex = Some(bytes);
                o.claim_sent_ms = now_ms();
                o.claim_batch = book["batch"].as_u64().unwrap_or(0);
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line and the public batch number; no note, amount or key.
                eprintln!("[defi] a claim was built and handed to custody at batch {}", o.claim_batch);
                in_flight.push(o);
            }
            Ok(None) => in_flight.push(o),
            // a claim the node would not take stays owed and is built again on the next pass: nothing was spent, and a status of "failed" would have stranded the fill or the refund for good
            Err(why) => {
                eprintln!("[defi] a claim was not taken yet: {why}");
                in_flight.push(o);
            }
        }
    }
    f.orders = in_flight;
    advance_payouts(&mut f);
    write_defi(&f)?;
    let orders: Vec<serde_json::Value> = f
        .orders
        .iter()
        .rev()
        .map(|o| {
            serde_json::json!({
                "coin": coin_name(o.pair),
                "sell": o.sell,
                "batch": o.batch,
                // ⭐ EARN — a deposit spends SAT and a withdrawal spends pool units (counted like SAT): both in SAT_UNIT
                "paid": o.amount as f64 / if o.sell || !o.kind.is_empty() { SAT_UNIT } else { coin_unit(o.pair) },
                "status": o.status,
                "got": o.out as f64 / if pays_coin(o) { coin_unit(o.pair) } else { SAT_UNIT },
                "pays_coin": pays_coin(o),
                "kind": if o.kind.is_empty() { "trade" } else { o.kind.as_str() },
                "created_ms": o.created_ms,
            })
        })
        .collect();
    let chain_now = crate::node_chain_time_ms();
    let payouts: Vec<serde_json::Value> = f
        .payouts
        .iter()
        .map(|p| {
            let pieces_left = usdmd_node::peg_pool::split_to_coin_denoms(coin_ledger(p.pair), p.left).0.len();
            // the latest moment a rung already handed over (or in flight) waits for: when the money on its way is all there
            let last_after = p.handed_after.iter().copied().chain(std::iter::once(p.next_pay_after)).max().unwrap_or(0);
            serde_json::json!({
                "coin": coin_name(p.pair),
                "to": p.to,
                "to_vault": p.pair == 0 && p.to.is_empty(),
                "left": p.left as f64 / coin_unit(p.pair),
                "sent": p.sent as f64 / coin_unit(p.pair),
                "auto_opsec": p.opsec,
                "pieces_left": pieces_left,
                "on_its_way_ms": last_after.saturating_sub(chain_now),
            })
        })
        .collect();
    let vault_rungs: Vec<serde_json::Value> = f
        .vault_rungs
        .iter()
        .rev()
        .take(64)
        .map(|v| serde_json::json!({ "address": v.address, "btc": v.amount as f64 / coin_unit(0), "arrives_in_ms": v.pay_after.saturating_sub(chain_now), "created_ms": v.created_ms }))
        .collect();
    Ok(serde_json::json!({ "orders": orders, "claimed": claimed, "intents": f.intents, "preparing": f.exact.len(), "payouts": payouts, "vault_rungs": vault_rungs }))
}

/// Whether `o`'s claim mints the coin: a seller's fill, a buyer's money back.
fn pays_coin(o: &DefiOrder) -> bool {
    match o.status.as_str() {
        "filled" => o.sell,
        "returned" => false,
        "above_max" | "refunded" => !o.sell,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ THE ORDER'S SECRET IS THE WALLET'S, PER ORDER: two orders of one wallet draw different blinds, two wallets differ, and
    /// the same wallet re-derives the same blind (from its words); every lane is a field element of the commitment (< 2^30).
    #[test]
    fn br15_buy_sat_order_secrets_are_per_wallet_per_order_and_rederivable() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(amount_blind_for(&a, 0), amount_blind_for(&a, 1), "two orders share a secret");
        assert_ne!(amount_blind_for(&a, 0), amount_blind_for(&b, 0), "two wallets share a secret");
        assert_eq!(amount_blind_for(&a, 7), amount_blind_for(&a, 7), "the secret is not re-derivable");
        assert!(amount_blind_for(&a, 3).iter().all(|l| *l < (1 << 30)), "a lane is not a field element");
    }

    /// ⭐ THE QUOTE IS THE CLAIM: what the screen shows a dollar amount buys at a tick is exactly what the claim relation pays.
    #[test]
    fn br15_buy_sat_quote_equals_the_claim_relation_payout() {
        for t in [-20_000i64, -9_000, 0, 693] {
            let x = 100 * 100_000_000u64;
            let no_max = ba::ORDER_BUCKETS - 1;
            let (p_num, p_den, _, _, _, out) = usdmd_node::defi_custody::claim_terms(x, no_max, false, Some((t, usdmd_node::defi_clear::j_min(t, t), true))).expect("fits");
            assert_eq!(sat_at(x, t), out, "the quote and the claim disagree at tick {t}");
            let g = ba::claim_out(x, p_num, p_den).expect("fits");
            assert_eq!(out, g - ba::claim_fee(g), "a filled buy is paid its fill less the fee on the SAT leg");
            // a +2 % order at a price 3 % above its batch's opening is refunded in full
            let (_, _, _, _, _, back) = usdmd_node::defi_custody::claim_terms(x, 0, false, Some((t + 30, usdmd_node::defi_clear::j_min(t, t + 30), true))).expect("fits");
            assert_eq!(back, x, "an order above its maximum is not refunded in full at tick {t}");
            // a sell pays the tick's own price, or its SAT back when the batch's sells did not count
            let (_, _, _, _, _, sold) = usdmd_node::defi_custody::claim_terms(x, no_max, true, Some((t, usdmd_node::defi_clear::j_min(t, t), true))).expect("fits");
            let (n, d) = usdmd_node::defi_clear::tick_ratio(t);
            assert_eq!(sold, ba::claim_out(x - ba::claim_fee(x), n, d).expect("fits"), "a sell's claim is not the tick's price over its SAT less the fee at tick {t}");
            assert_eq!(coin_at(0, x as f64 / SAT_UNIT, t), sold as f64 / coin_unit(0), "the sell quote and the claim disagree at tick {t}");
            let (_, _, _, _, _, kept) = usdmd_node::defi_custody::claim_terms(x, no_max, true, Some((t, usdmd_node::defi_clear::j_min(t, t), false))).expect("fits");
            assert_eq!(kept, x, "a sell whose batch's sells did not count does not get its SAT back at tick {t}");
        }
    }
}

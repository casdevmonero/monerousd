// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-4 + §BR-7 — BORROWING AGAINST BITCOIN AS STANDARD DEBT UNITS (docs/BR-4-7-PRIVATE-POSITIONS-SPEC-20261029.md
//! §10–§10.3).
//!
//! A position is a set of UNITS. One unit owes `U` USDm (a ladder size) and is backed by its price band's collateral
//! `c(U, k)` — 110 % of `U` at the band's lower price. A unit's note binds its band, size, the day it opened and its band's
//! epoch (all known when the unit is built, and checked EXACTLY at the fold), so the node keeps no per-unit row: only each
//! cell's open count and each band's epoch (a band liquidation closes its epoch). Interest is a pure function of the day.
//! Every unit in a cell is identical, so the counts are public without exposing any position, and a position's units open
//! one per object at sealed random delays (a position's size never appears at once).
//!
//! WHY NO REDEMPTION AGAINST UNITS (§10.3): every USDm is backed by the one reserve, which pays $1 of Bitcoin (at the 7-day
//! TWAP) to anyone who cashes out — the hard floor. A unit's claim is its own collateral minus its debt, so a cash-out of
//! a unit-minted dollar removes one dollar of claim and one dollar of reserve together: solvency is untouched, and the band
//! liquidation protects the rest. Liquity redeems against troves because it has no reserve to redeem from.
//!
//! BORROWED: Liquity (110 % individual floor, ≥ 150 % system via the existing bound transition = recovery mode by
//! construction), crvUSD (price bands), Whirlpool (fixed denominations). Pure integer math; every rounding favours the
//! system (collateral rounds UP at open, debt rounds UP at close).

use serde::{Deserialize, Serialize};

/// Unit sizes in USDm atomic (1 USDm = 1e8): 10, 100, 1,000, 10,000 USDm.
pub const UNIT_ATOMIC: [u128; 4] = [1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000];
/// The number of price bands (geometric, ×1.25 per band, from $1,000).
pub const BANDS: usize = 64;
/// The lowest band's lower price, USD per BTC.
pub const BAND_BASE_USD: u128 = 1_000;
/// The individual floor: a unit is backed by 110 % of its debt at its band's lower price.
pub const UNIT_RATIO_BPS: u128 = 11_000;
/// The borrowing rate (APR, basis points) — paid at close into the stakers' pool (the holder yield, §1.5).
pub const UNIT_RATE_BPS: u128 = 200;
/// One day of the chain's clock (median-time-past, `Node::chain_time_ms_at`): a unit's day is its carrying block's chain time ÷
/// this. A unit's open day and its close day are both read from their carrying blocks, so every node computes the same
/// interest. ⛔ A TIME, NEVER A COUNT OF BLOCKS (A-F60's class): this was 172,800 blocks, a day only at 500 ms blocks.
pub const DAY_MS: u64 = crate::params::DAY_MS;
/// Fixed-point scale of the interest index.
pub const I_SCALE: u128 = 1_000_000_000_000_000_000;
const DAYS_PER_YEAR: u128 = 365;

pub const CELLS: usize = BANDS * UNIT_ATOMIC.len();

/// The band's lower price in USD per BTC, × 1e6 (exact: ×1.25 = ×5/4 per band, carried at micro-dollar precision).
#[must_use]
pub fn band_price_micro_usd(k: usize) -> u128 {
    let mut p = BAND_BASE_USD * 1_000_000;
    for _ in 0..k.min(BANDS - 1) {
        p = p * 5 / 4;
    }
    p
}

/// The chain's price word for the band's lower price: USDm atomic per sat × `liquidation::PRICE_SCALE`
/// (one sat at $P per BTC is P × 1e-8 USD = P USDm atomic, so the word is P × PRICE_SCALE).
#[must_use]
pub fn band_price_word(k: usize) -> u128 {
    band_price_micro_usd(k) * crate::liquidation::PRICE_SCALE / 1_000_000
}

/// The band a price word sits in (`None` below the lowest band).
#[must_use]
pub fn band_of_price(price_word: u128) -> Option<usize> {
    (0..BANDS).rev().find(|k| price_word >= band_price_word(*k))
}

/// The exact 110 % floor in sats: 110 % of a unit's debt at its band's lower price, rounded UP to the sat — what the peg-in
/// carrier's `Marginal` gate proves (DB-470).
#[must_use]
pub fn collateral_floor_sats(l: usize, k: usize) -> u128 {
    let u = UNIT_ATOMIC[l.min(UNIT_ATOMIC.len() - 1)];
    let num = u * UNIT_RATIO_BPS * crate::liquidation::PRICE_SCALE;
    let den = 10_000 * band_price_word(k.min(BANDS - 1));
    num.div_ceil(den)
}

/// The smallest payout piece (`peg_pool::PAYOUT_DENOMS[0]`): a unit's collateral is a multiple of it.
pub const COLLATERAL_STEP_SATS: u128 = 10_000;

/// ⭐ A unit's collateral in sats: the 110 % floor rounded UP to a whole payout piece (§10.4), so the close releases it exactly
/// in payout-ladder pieces that mix with every cash-out. Cost: under 10,000 sats more locked per unit, all of it returned.
#[must_use]
pub fn collateral_sats(l: usize, k: usize) -> u128 {
    collateral_floor_sats(l, k).div_ceil(COLLATERAL_STEP_SATS) * COLLATERAL_STEP_SATS
}

/// The interest index on `day` (compounded daily from genesis): a pure function — no state, one answer on every node.
#[must_use]
pub fn interest_index(day: u64) -> u128 {
    // square-and-multiply on the daily factor (1 + r/365) in I_SCALE fixed point: O(log day) work
    let factor = I_SCALE + I_SCALE * UNIT_RATE_BPS / (10_000 * DAYS_PER_YEAR);
    let (mut acc, mut base, mut e) = (I_SCALE, factor, day);
    while e > 0 {
        if e & 1 == 1 {
            acc = mul_fix(acc, base);
        }
        e >>= 1;
        if e > 0 {
            base = mul_fix(base, base);
        }
    }
    acc
}

/// `a × b / I_SCALE` without overflowing u128 for indices up to ~1e20 × I_SCALE (split into high and low halves).
fn mul_fix(a: u128, b: u128) -> u128 {
    let (ah, al) = (a / I_SCALE, a % I_SCALE);
    let (bh, bl) = (b / I_SCALE, b % I_SCALE);
    ah * bh * I_SCALE + ah * bl + al * bh + al * bl / I_SCALE
}

#[must_use]
pub fn cell_index(k: usize, l: usize) -> Option<usize> {
    (k < BANDS && l < UNIT_ATOMIC.len()).then(|| k * UNIT_ATOMIC.len() + l)
}

/// What a unit's note binds (its asset tag) and its close reveals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitTerms {
    pub k: u8,
    pub l: u8,
    /// The day it opened (the carrying block's price-epoch day, checked exactly at the fold).
    pub day: u64,
    /// Its band's epoch at open (checked exactly at the fold; a later band liquidation closes it).
    pub epoch: u64,
}

impl UnitTerms {
    /// The unit's 32-byte asset id: binds the band, size, day and band epoch.
    #[must_use]
    pub fn tag_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("MUSD/debt-unit/tag/v2");
        h.update(&[self.k, self.l]);
        h.update(&self.day.to_le_bytes());
        h.update(&self.epoch.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// The unit note's asset tag (the circuit's three limbs, never the USDm tag) — the note's value is `U`, so value + tag
    /// bind everything the close needs.
    #[must_use]
    pub fn tag(&self) -> [u64; 3] {
        usdm_decider::whir_rec_block::wrapped_asset_tag(&self.tag_id())
    }

    #[must_use]
    pub fn unit_atomic(&self) -> Option<u128> {
        if (self.k as usize) < BANDS {
            UNIT_ATOMIC.get(self.l as usize).copied()
        } else {
            None
        }
    }
}

/// What a close owes and gets back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseTerms {
    /// USDm atomic the owner burns: `U × I(today) / I(open day)`, rounded UP.
    pub debt_atomic: u128,
    /// The interest part of it (credited to the stakers' pool, not burned).
    pub interest_atomic: u128,
    /// Sats released to the owner.
    pub sats: u128,
}

/// The public book: each cell's open units and each band's epoch, as fixed-length vectors (`CELLS` and `BANDS` long — the
/// one shape; a book of any other length is refused by [`UnitBook::is_well_formed`] at adopt).
/// O1-FOOTPRINT-REVIEWED: 256 + 64 words (2.5 KB), constant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitBook {
    pub open: Vec<u64>,
    pub band_epoch: Vec<u64>,
}

impl Default for UnitBook {
    fn default() -> Self {
        UnitBook { open: vec![0; CELLS], band_epoch: vec![0; BANDS] }
    }
}

impl UnitBook {
    /// The book has its one shape (a carried book of another length is refused, never padded).
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.open.len() == CELLS && self.band_epoch.len() == BANDS
    }

    #[must_use]
    pub fn epoch_of(&self, k: usize) -> Option<u64> {
        self.band_epoch.get(k).copied()
    }

    #[must_use]
    pub fn open_in(&self, k: usize, l: usize) -> Option<u64> {
        self.open.get(cell_index(k, l)?).copied()
    }

    /// The book's total open principal (USDm atomic) — public by design (identical units, public counts).
    #[must_use]
    pub fn principal(&self) -> u128 {
        self.open.iter().enumerate().map(|(i, n)| UNIT_ATOMIC[i % UNIT_ATOMIC.len()] * u128::from(*n)).sum()
    }

    /// Admit one unit at the fold: its declared epoch must be its band's current epoch and its declared day the carrying
    /// block's day (`today`), else it is refused (the wallet builds it again — nothing was minted).
    pub fn open_unit(&mut self, t: &UnitTerms, today: u64) -> Result<(), &'static str> {
        let i = cell_index(t.k as usize, t.l as usize).ok_or("no such cell")?;
        if t.day != today {
            return Err("the unit names another day than its carrying block's");
        }
        if Some(t.epoch) != self.epoch_of(t.k as usize) {
            return Err("the unit names a band epoch that is not current");
        }
        let n = self.open.get_mut(i).ok_or("the book is malformed")?;
        *n = n.checked_add(1).ok_or("the cell is full")?;
        Ok(())
    }

    /// The terms a unit closes on (read-only). A unit whose band epoch has since closed was liquidated: it owes nothing and
    /// gets nothing back (its collateral now backs the reserve, its debt was cancelled).
    #[must_use]
    pub fn close_terms(&self, t: &UnitTerms, today: u64) -> Option<CloseTerms> {
        let u = t.unit_atomic()?;
        let cur = self.epoch_of(t.k as usize)?;
        if t.epoch > cur || t.day > today {
            return None;
        }
        if t.epoch < cur {
            return Some(CloseTerms { debt_atomic: 0, interest_atomic: 0, sats: 0 });
        }
        let debt = (u * interest_index(today)).div_ceil(interest_index(t.day));
        Some(CloseTerms { debt_atomic: debt, interest_atomic: debt - u, sats: collateral_sats(t.l as usize, t.k as usize) })
    }

    /// Apply a close at the fold (the door has checked the note, the burn and the terms). A liquidated unit's close moves
    /// no count (its cell was emptied by the liquidation).
    pub fn close_unit(&mut self, t: &UnitTerms) -> Result<(), &'static str> {
        let i = cell_index(t.k as usize, t.l as usize).ok_or("no such cell")?;
        let cur = self.epoch_of(t.k as usize).ok_or("the book is malformed")?;
        if t.epoch < cur {
            return Ok(());
        }
        let n = self.open.get_mut(i).ok_or("the book is malformed")?;
        *n = n.checked_sub(1).ok_or("no open unit in this cell")?;
        Ok(())
    }

    /// ⭐ A guarded mark below band `k`'s lower price liquidates band `k`: its cells empty and its epoch closes. Returns the
    /// principal cancelled and the collateral forfeited to the reserve (sats). Permissionless: every input is public.
    pub fn liquidate_band(&mut self, k: usize) -> (u128, u128) {
        let (mut debt, mut sats) = (0u128, 0u128);
        let mut any = false;
        for l in 0..UNIT_ATOMIC.len() {
            let Some(n) = cell_index(k, l).and_then(|i| self.open.get_mut(i)) else { continue };
            if *n > 0 {
                debt += UNIT_ATOMIC[l] * u128::from(*n);
                sats += collateral_sats(l, k) * u128::from(*n);
                *n = 0;
                any = true;
            }
        }
        if any {
            if let Some(e) = self.band_epoch.get_mut(k) {
                *e += 1;
            }
        }
        (debt, sats)
    }

    /// Every band whose lower price is above `mark` (each unit there is under 110 %) is liquidated. Returns the totals.
    pub fn liquidate_below(&mut self, mark: u128) -> (u128, u128) {
        let (mut d, mut s) = (0u128, 0u128);
        for k in 0..BANDS {
            if band_price_word(k) > mark {
                let (dd, ss) = self.liquidate_band(k);
                d += dd;
                s += ss;
            }
        }
        (d, s)
    }
}

/// TWO-PARTY-REVIEWED: these are the ledger's pure arithmetic (one book, no boundary crossed); the two-node agreement — one
/// node produces the unit objects, a second ingests the block and holds the same book — is the node pin
/// `node::pins::br4_*` built on this module.
#[cfg(test)]
mod tests {

    /// ⭐ R7 A5 — THE COMPARISON TABLE NAMES THE CODE'S OWN FIGURES: docs/A5-ADOPTABLE-COMPARISON-20261030.md states each of
    /// MonerousD's lines with the constant it is read from; a constant that moves without the table moving fails here, so the
    /// published comparison can never advertise a figure the chain or the wallet does not charge.
    #[test]
    fn the_a5_table_names_the_codes_own_figures() {
        // this test runs in the ledger crate, whose manifest is monerousd-node-zkdag/ledger: the repository root is two up
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let table = std::fs::read_to_string(format!("{root}/docs/A5-ADOPTABLE-COMPARISON-20261030.md")).expect("the A5 table reads");
        let wallet = std::fs::read_to_string(format!("{root}/monerousd-wallet-v2/src-tauri/src/lib.rs")).expect("the wallet core reads");
        let pct = |bps: u128| format!("{}", bps as f64 / 100.0);
        for (name, value, shown) in [
            ("UNIT_RATIO_BPS", UNIT_RATIO_BPS, format!("{} %", pct(UNIT_RATIO_BPS))),
            ("UNIT_RATE_BPS", UNIT_RATE_BPS, format!("{} % APR", pct(UNIT_RATE_BPS))),
            ("DEFAULT_MINT_RATIO_BPS", u128::from(crate::peg::DEFAULT_MINT_RATIO_BPS), format!("{} %", pct(u128::from(crate::peg::DEFAULT_MINT_RATIO_BPS)))),
        ] {
            let constant = format!("{name} = {}", group(value));
            assert!(table.contains(&constant), "⛔ A5: the table does not name {constant}");
            assert!(table.contains(&shown), "⛔ A5: the table does not show {name} as {shown}");
        }
        let fee = u128::from(usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC);
        assert!(table.contains(&format!("PROTOCOL_FEE_ATOMIC = {}", group(fee))), "⛔ A5: the table's base fee is not the protocol's");
        assert_eq!(fee, 100_000, "⛔ A5: the protocol fee moved off $0.001 — update the table's dollar figure");
        for (name, bps) in [("FEE_BPS_SWAP", 25u64), ("FEE_BPS_CASH", 10), ("FEE_BPS_POS", 50)] {
            assert!(wallet.contains(&format!("const {name}: u64 = {bps};")), "⛔ A5: the wallet's {name} is no longer {bps} bps — update the table");
            assert!(table.contains(&format!("{name} = {bps}")), "⛔ A5: the table does not name {name} = {bps}");
        }
    }

    /// `11000` → `11_000` (the table writes constants as the source does).
    fn group(v: u128) -> String {
        let d = v.to_string();
        let mut out = String::new();
        for (i, c) in d.chars().enumerate() {
            if i > 0 && (d.len() - i) % 3 == 0 {
                out.push('_');
            }
            out.push(c);
        }
        out
    }
    use super::*;

    const BTC_60K: u128 = 60_000 * crate::liquidation::PRICE_SCALE;

    #[test]
    fn a_unit_is_backed_by_110_percent_at_its_band_and_bands_are_geometric() {
        let k = band_of_price(BTC_60K).expect("60k is inside the ladder");
        assert!(band_price_word(k) <= BTC_60K && BTC_60K < band_price_word(k + 1));
        for l in 0..UNIT_ATOMIC.len() {
            let c = collateral_sats(l, k);
            let value_at_band = c * band_price_word(k) / crate::liquidation::PRICE_SCALE;
            assert!(value_at_band * 10_000 >= UNIT_ATOMIC[l] * UNIT_RATIO_BPS, "⛔ a unit below 110 % at its band");
            let f = collateral_floor_sats(l, k);
            let less = (f - 1) * band_price_word(k) / crate::liquidation::PRICE_SCALE;
            assert!(less * 10_000 < UNIT_ATOMIC[l] * UNIT_RATIO_BPS, "the floor is exact (one sat less is under)");
            assert!(c % COLLATERAL_STEP_SATS == 0 && c >= f && c - f < COLLATERAL_STEP_SATS, "⛔ the collateral is not the floor rounded up to a payout piece");
            let (pieces, rest) = crate::peg_pool::split_to_denoms(u64::try_from(c).unwrap());
            assert_eq!(rest, 0, "⛔ the collateral does not split exactly into payout pieces: {pieces:?}");
        }
        assert_eq!(band_price_micro_usd(1) * 4, band_price_micro_usd(0) * 5);
    }

    /// REFUTER 1 (the fold's exact checks): a unit naming another day or a stale band epoch is refused and moves nothing.
    #[test]
    fn a_unit_naming_another_day_or_a_closed_band_epoch_is_refused_at_the_fold() {
        let mut book = UnitBook::default();
        let k = band_of_price(BTC_60K).unwrap() - 4;
        let t = UnitTerms { k: k as u8, l: 1, day: 10, epoch: 0 };
        assert!(book.open_unit(&UnitTerms { day: 9, ..t }, 10).is_err(), "⛔ another day admitted");
        assert!(book.open_unit(&UnitTerms { epoch: 1, ..t }, 10).is_err(), "⛔ a future epoch admitted");
        assert_eq!(book, UnitBook::default(), "a refused unit moved the book");
        book.open_unit(&t, 10).expect("the honest unit opens");
        assert_eq!(book.open_in(k, 1), Some(1));
        book.liquidate_band(k);
        assert!(book.open_unit(&t, 10).is_err(), "⛔ a unit naming the closed epoch admitted after its band liquidated");
        assert!(UnitBook { open: vec![0; 3], band_epoch: vec![0; BANDS] }.open_unit(&t, 10).is_err(), "⛔ a malformed book admits");
        assert!(!UnitBook { open: vec![0; 3], band_epoch: vec![0; BANDS] }.is_well_formed());
    }

    /// REFUTER 5: a guarded mark below band k's price liquidates exactly the bands above the mark; a liquidated unit owes and
    /// gets nothing; a unit in a band below the mark is untouched.
    #[test]
    fn a_mark_below_a_band_liquidates_exactly_the_bands_above_it() {
        let mut book = UnitBook::default();
        let k = band_of_price(BTC_60K).unwrap();
        let near = UnitTerms { k: (k - 1) as u8, l: 0, day: 0, epoch: 0 };
        let safe = UnitTerms { k: (k - 6) as u8, l: 0, day: 0, epoch: 0 };
        book.open_unit(&near, 0).unwrap();
        book.open_unit(&safe, 0).unwrap();
        let mark = band_price_word(k - 1) - 1; // just under the near band's floor
        let (debt, sats) = book.liquidate_below(mark);
        assert_eq!(debt, UNIT_ATOMIC[0], "exactly the near unit's principal is cancelled");
        assert_eq!(sats, collateral_sats(0, k - 1));
        assert_eq!(book.close_terms(&near, 3).unwrap(), CloseTerms { debt_atomic: 0, interest_atomic: 0, sats: 0 });
        let s = book.close_terms(&safe, 3).unwrap();
        assert_eq!(s.sats, collateral_sats(0, k - 6), "⛔ the safe band moved");
        assert!(s.debt_atomic > UNIT_ATOMIC[0], "the safe unit owes its interest");
        assert!(book.close_terms(&UnitTerms { epoch: 9, ..near }, 3).is_none(), "a future epoch is refused");
        assert!(book.close_terms(&UnitTerms { day: 4, ..safe }, 3).is_none(), "a future open day is refused");
    }

    /// REFUTER 4: after `n` days a unit owes `U · I(n) / I(0)`: 2 % APR compounded daily.
    #[test]
    fn interest_is_a_pure_function_of_the_day_at_two_percent_apr() {
        assert_eq!(interest_index(0), I_SCALE);
        let year = interest_index(365);
        let expect = I_SCALE * 10_202 / 10_000; // (1 + 0.02/365)^365 ≈ 1.020201
        assert!(year.abs_diff(expect) * 10_000 < I_SCALE, "a year at 2 % compounds to ≈ 1.0202, got {year}");
        let mut book = UnitBook::default();
        let t = UnitTerms { k: 40, l: 2, day: 100, epoch: 0 };
        book.open_unit(&t, 100).unwrap();
        let c = book.close_terms(&t, 130).unwrap();
        let approx = UNIT_ATOMIC[2] * 200 * 30 / (10_000 * 365);
        assert!(c.interest_atomic.abs_diff(approx) * 100 < approx, "30 days ≈ {approx}, got {}", c.interest_atomic);
        assert_eq!(c.debt_atomic, UNIT_ATOMIC[2] + c.interest_atomic);
        assert!(interest_index(36_500) > interest_index(36_499), "the index never overflows inside a century");
    }

    #[test]
    fn closing_empties_the_cell_and_a_liquidated_close_moves_no_count() {
        let mut book = UnitBook::default();
        let a = UnitTerms { k: 30, l: 3, day: 1, epoch: 0 };
        book.open_unit(&a, 1).unwrap();
        book.open_unit(&a, 1).unwrap();
        assert_eq!(book.principal(), 2 * UNIT_ATOMIC[3]);
        book.close_unit(&a).unwrap();
        book.close_unit(&a).unwrap();
        assert!(book.close_unit(&a).is_err(), "⛔ a third close of two units");
        assert_eq!(book, UnitBook::default(), "the cell empties exactly");
        book.open_unit(&a, 1).unwrap();
        book.liquidate_band(30);
        book.close_unit(&a).expect("a liquidated unit's close is a no-op on the counts");
        assert_eq!(book.principal(), 0);
    }
}

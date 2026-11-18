// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §BR-4 — THE 7-DAY TIME-WEIGHTED AVERAGE AND THE 30-DAY LOW of an asset's certified price mark, in ONE fixed-size word set
//! per asset (spec §1 item 7: minting and redemptions use the 7-day TWAP; §2 item 5 / §17.5: repayment values SAT at
//! min(7-day TWAP, 30-day low) × the haircut).
//!
//! BORROWED: Uniswap v2's cumulative-price accumulator (`price0CumulativeLast`: Σ price × elapsed, a TWAP being the difference
//! of two readings over their span) and Uniswap v3's bounded observation ring (a fixed cardinality of snapshots overwritten in
//! place, so the oracle never grows). Here the clock is the price epoch (`price_mark_tx` epochs: 1,200 blocks at the 500 ms
//! target = 10 minutes, 144 per day), the ring holds the accumulator at each of the last 8 day boundaries (a 7-day window
//! needs the reading from 7 days back), and a second ring holds each of the last 30 days' lowest mark.
//!
//! ORDER-INDEPENDENT BY CONSTRUCTION: a mark joins the history only when a mark of a LATER epoch supersedes it
//! (`PegLedger::mark_price_attested`), i.e. when its epoch is closed. Within an epoch the standing mark can still be replaced
//! by a higher-ranked one (DB-245's maximum), so folding it earlier would let arrival order pick which same-epoch mark entered
//! the low; folding the CLOSED epoch's standing mark is a pure function of the canonical fold. Every node folds the same
//! blocks in the same canonical order (GHOSTDAG), so every node holds the same words.
//!
//! NO-GROWTH: 8 + 30 + 5 words per registered asset, forever. Bounded work: a gap of any length rolls at most 31 days.
//! DIGITAL-CASH-PRIVACY-REVIEWED: a function of the public certified price marks only — no value, identity or owner.

use serde::{Deserialize, Serialize};

/// Price epochs per day: 86,400 s / (1,200 blocks × 0.5 s).
pub const EPOCHS_PER_DAY: u64 = 144;
/// The TWAP window, in days (spec §1 item 7).
pub const TWAP_DAYS: u64 = 7;
/// The low window, in days (spec §2 item 5).
pub const LOW_DAYS: u64 = 30;
const START_RING: usize = 8; // TWAP_DAYS + 1 day boundaries
const LOW_RING: usize = 30; // LOW_DAYS
/// ⭐ §BR-4 liquidation guard (the OSM delay): how many CONSECUTIVE closed epochs' marks must stand beyond the TWAP band, on
/// one side, before a mark beyond that band may act on a liquidation — 6 epochs = one hour at 144 epochs a day (MakerDAO's
/// Oracle Security Module delays a price by one hour). One outlier epoch can never liquidate; a real move liquidates one hour
/// after it crosses the band and keeps liquidating as it deepens.
pub const GUARD_PERSIST_EPOCHS: usize = 6;

/// One asset's price history: the cumulative price, the ring of day-boundary readings and the ring of daily lows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceHistory {
    /// The epoch of the first folded mark (0 with `samples == 0`: empty).
    pub first_epoch: u64,
    /// The epoch and price of the last folded mark; it holds until the next folded mark.
    pub last_epoch: u64,
    pub last_price: u128,
    /// Σ price × epochs from `first_epoch` to `last_epoch` (each mark weighted by how long it stood).
    pub cum: u128,
    /// The number of marks folded (saturating; only "none yet" matters).
    pub samples: u64,
    /// `starts[d % 8]` = the accumulator at the first epoch of day `d`, for the last 8 days.
    pub starts: [u128; START_RING],
    /// `lows[d % 30]` = the lowest price standing during day `d` (0 = no sample that day), for the last 30 days.
    pub lows: [u128; LOW_RING],
    /// The last [`GUARD_PERSIST_EPOCHS`] CLOSED marks, newest last (zero = no mark yet). O1-FOOTPRINT-REVIEWED: a constant ring.
    #[serde(default)]
    pub recent: [u128; GUARD_PERSIST_EPOCHS],
    /// Beside each `recent` mark: the 7-day average that stood when it was folded (0 = none yet) — the reference it was judged
    /// against AT ITS OWN EPOCH. MEASURED 2026-11-02 (the crash pin): judging old marks against today's average let a sustained
    /// crash chase its own band (the average falls with the crash, so an hour-old mark reads "inside" again) and the guard
    /// refused seven epochs running; the OSM asks whether the price stood outside the band for an hour, each reading at its time.
    #[serde(default)]
    pub recent_ref: [u128; GUARD_PERSIST_EPOCHS],
}

impl PriceHistory {
    fn day_of(epoch: u64) -> u64 {
        epoch / EPOCHS_PER_DAY
    }

    /// The accumulator at `epoch` (≥ `last_epoch`), the last price standing since.
    fn cum_at(&self, epoch: u64) -> u128 {
        self.cum.saturating_add(self.last_price.saturating_mul(u128::from(epoch.saturating_sub(self.last_epoch))))
    }

    /// Fold the CLOSED epoch `epoch`'s standing mark `price`. An epoch at or before the last folded one changes nothing
    /// (`false`): the fold is monotone in the price epoch. A zero price is refused (no mark is priced at zero).
    pub fn fold(&mut self, epoch: u64, price: u128) -> bool {
        if price == 0 {
            return false;
        }
        if self.samples == 0 {
            self.first_epoch = epoch;
            self.last_epoch = epoch;
            self.last_price = price;
            self.cum = 0;
            self.samples = 1;
            self.push_recent(price, 0);
            let d = Self::day_of(epoch);
            self.starts = [0; START_RING];
            self.lows = [0; LOW_RING];
            self.lows[(d % LOW_RING as u64) as usize] = price;
            return true;
        }
        if epoch <= self.last_epoch {
            return false;
        }
        let (from_day, to_day) = (Self::day_of(self.last_epoch), Self::day_of(epoch));
        // Roll every day boundary crossed since the last mark — at most the last 31 (older slots are overwritten anyway):
        // the boundary's reading is exact (the last price stood until then), and a day the last price stood through whole
        // has that price as its low.
        let first_new = from_day.saturating_add(1).max(to_day.saturating_sub(LOW_RING as u64));
        for d in first_new..=to_day {
            if d <= from_day {
                continue;
            }
            let boundary = d.saturating_mul(EPOCHS_PER_DAY);
            self.starts[(d % START_RING as u64) as usize] = self.cum_at(boundary);
            self.lows[(d % LOW_RING as u64) as usize] = self.last_price; // it stood at the day's first epoch
        }
        let reference = self.twap7().unwrap_or(0);
        self.cum = self.cum_at(epoch);
        self.last_epoch = epoch;
        self.last_price = price;
        self.samples = self.samples.saturating_add(1);
        self.push_recent(price, reference);
        let slot = &mut self.lows[(to_day % LOW_RING as u64) as usize];
        *slot = if *slot == 0 { price } else { (*slot).min(price) };
        true
    }

    /// The time-weighted average price over the last `TWAP_DAYS` days ending at the last folded mark's epoch — over the
    /// whole history while it is shorter than the window (the launch weeks), and the last mark itself while the history is a
    /// single mark. `None` while empty.
    #[must_use]
    pub fn twap7(&self) -> Option<u128> {
        if self.samples == 0 {
            return None;
        }
        let day = Self::day_of(self.last_epoch);
        let first_day = Self::day_of(self.first_epoch);
        let (start_epoch, start_cum) = if day >= first_day.saturating_add(TWAP_DAYS) {
            let d = day - TWAP_DAYS;
            (d.saturating_mul(EPOCHS_PER_DAY), self.starts[(d % START_RING as u64) as usize])
        } else {
            (self.first_epoch, 0)
        };
        let span = self.last_epoch.saturating_sub(start_epoch);
        if span == 0 {
            return Some(self.last_price);
        }
        Some(self.cum.saturating_sub(start_cum) / u128::from(span))
    }

    /// The lowest price standing during the last `LOW_DAYS` days ending at the last folded mark's day. `None` while empty.
    fn push_recent(&mut self, price: u128, reference: u128) {
        self.recent.rotate_left(1);
        self.recent[GUARD_PERSIST_EPOCHS - 1] = price;
        self.recent_ref.rotate_left(1);
        self.recent_ref[GUARD_PERSIST_EPOCHS - 1] = reference;
    }

    /// ⭐ §BR-4 liquidation guard — has a move beyond the band PERSISTED? True iff every one of the last
    /// [`GUARD_PERSIST_EPOCHS`] closed marks stood beyond `band_bps` of the 7-day average THAT STOOD WHEN IT WAS FOLDED, on
    /// `mark`'s side of `twap` (below for a mark below, above for a mark above). Fewer closed marks than the window, a mark
    /// folded before any average existed, or any one inside its band or on the other side, is false: the move is not yet known
    /// to be real.
    #[must_use]
    pub fn move_persisted(&self, twap: u128, band_bps: u64, mark: u128) -> bool {
        let below = mark < twap;
        self.recent.iter().zip(self.recent_ref.iter()).all(|(p, r)| {
            if *p == 0 || *r == 0 {
                return false;
            }
            let band = r.saturating_mul(u128::from(band_bps)) / 10_000;
            if below {
                *p < r.saturating_sub(band)
            } else {
                *p > r.saturating_add(band)
            }
        })
    }

    #[must_use]
    pub fn low30(&self) -> Option<u128> {
        if self.samples == 0 {
            return None;
        }
        let day = Self::day_of(self.last_epoch);
        let first_day = Self::day_of(self.first_epoch);
        let oldest = day.saturating_sub(LOW_DAYS - 1).max(first_day);
        (oldest..=day)
            .map(|d| self.lows[(d % LOW_RING as u64) as usize])
            .filter(|p| *p > 0)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ §BR-4 — THE TWAP IS THE TIME-WEIGHTED MEAN OF THE LAST SEVEN DAYS, AND THE LOW IS THE LOWEST OF THE LAST THIRTY.
    /// A price of 100 for 20 days, 40 for one hour on day 20, then 200 for 10 days: the TWAP after day 30 reads exactly 200
    /// (the dip is out of its window), the low reads 40 (inside its window), and 31 days later the low forgets the dip.
    /// TAMPERS: a mark at or before the last folded epoch changes nothing; a zero price is refused; a fold that skipped
    /// the time weighting (the plain mean of marks) would read the TWAP of an hour-long spike as half the window.
    #[test]
    fn the_twap_weights_by_time_over_seven_days_and_the_low_spans_thirty() {
        let e = |day: u64, ep: u64| day * EPOCHS_PER_DAY + ep;
        let mut h = PriceHistory::default();
        assert_eq!((h.twap7(), h.low30()), (None, None), "empty");
        assert!(h.fold(e(0, 0), 100));
        assert_eq!(h.twap7(), Some(100), "a single mark is its own average");
        assert!(h.fold(e(20, 0), 40), "the dip at day 20");
        assert!(h.fold(e(20, 6), 200), "an hour later, 200");
        assert!(!h.fold(e(20, 6), 1), "⛔ a mark at the last folded epoch moved the history");
        assert!(!h.fold(e(19, 0), 1), "⛔ an earlier epoch moved the history");
        assert!(!h.fold(e(21, 0), 0), "⛔ a zero price folded");
        assert!(h.fold(e(30, 0), 200));
        assert_eq!(h.twap7(), Some(200), "⛔ the 7-day TWAP reached back past its window");
        assert_eq!(h.low30(), Some(40), "the dip sits inside the 30-day window");
        // an hour-long spike: the time-weighted mean barely moves; a plain mean of marks would read (200 + 10,000) / 2
        assert!(h.fold(e(31, 0), 10_000));
        assert!(h.fold(e(31, 6), 200));
        let twap = h.twap7().expect("held");
        assert!(twap < 300, "⛔ a one-hour spike moved the 7-day TWAP to {twap} (time weighting skipped)");
        assert!(h.fold(e(51, 0), 200), "past day 50: the dip (day 20) left the 30-day window");
        assert_eq!(h.low30(), Some(200), "⛔ the low remembered a dip older than 30 days");
        // a gap of a year rolls at most 31 days and reads the standing price
        assert!(h.fold(e(400, 0), 300));
        assert_eq!(h.low30(), Some(200), "the 200 stood through the window's early days");
        assert!(h.fold(e(431, 0), 300));
        assert_eq!((h.twap7(), h.low30()), (Some(300), Some(300)), "a month at 300 reads 300 on both");
    }

    /// ⭐ §BR-4 THE GUARD'S PERSISTENCE (MakerDAO's OSM hour): a move beyond the band has persisted only when every one of the
    /// last GUARD_PERSIST_EPOCHS closed marks stood beyond it on the mark's side. Fewer closed marks than the window, one mark
    /// back inside the band, or one on the other side: not persisted. TAMPER: a window of five crash marks and one inside
    /// (an outlier rejoining the band) reads false; six crash marks read true; a mark ABOVE the band asks the other side.
    #[test]
    fn a_move_beyond_the_band_has_persisted_only_after_the_whole_window_stood_beyond_it() {
        let bps = 2_500u64;
        let mut h = PriceHistory::default();
        // a week at 1,000, then a crash to 500: each 500 is judged against the average that stood when it was folded
        // (1,000 → 791 after five of them), and 500 is beyond 25 % of every one of those
        for i in 0..7u64 {
            assert!(h.fold(i + 1, 1_000));
        }
        assert!(!h.move_persisted(1_000, bps, 400), "⛔ a flat week counts as a persisted move");
        for i in 0..5u64 {
            assert!(h.fold(8 + i, 500));
            let t = h.twap7().expect("held");
            assert!(!h.move_persisted(t, bps, 480), "⛔ {} crash marks already count as persisted", i + 1);
        }
        assert!(h.fold(13, 500));
        let t = h.twap7().expect("held");
        assert!(h.move_persisted(t, bps, 480), "six crash marks, each beyond its own reading's band: persisted");
        assert!(!h.move_persisted(t, bps, 1_400), "⛔ a mark ABOVE the band is read against marks BELOW it");
        assert!(h.fold(14, 900), "a mark back inside its band (the average is ≈ 770 here)");
        let t = h.twap7().expect("held");
        assert!(!h.move_persisted(t, bps, 480), "⛔ a window holding a mark inside the band reads persisted");
        for i in 15..20u64 {
            assert!(h.fold(i, 400));
        }
        let t = h.twap7().expect("held");
        assert!(!h.move_persisted(t, bps, 380), "five after the rejoin: the window still holds the inside mark");
        assert!(h.fold(20, 400));
        let t = h.twap7().expect("held");
        assert!(h.move_persisted(t, bps, 380), "six again: persisted");
        // the first mark of a history has no reference: it never counts as beyond
        let mut fresh = PriceHistory::default();
        for i in 0..6u64 {
            assert!(fresh.fold(i + 1, 100));
        }
        assert!(!fresh.move_persisted(1_000, bps, 90), "⛔ marks folded before any average existed count as beyond");
    }
}

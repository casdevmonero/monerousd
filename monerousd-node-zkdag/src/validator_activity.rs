// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 — THE RUN-AND-FORGET VALIDATOR'S RULES (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §22; user 2026-10-30: "once its
//! activated by bonding then nothing more is needed").
//!
//! Four pure rules, each a function of chain objects the fold already applies — no new door:
//! 1. **Activity is chain state** ([`ActivityLedger`]): per seated validator, the last window (reward-epoch hour) in which any
//!    of its signed objects applied, and how many windows it was active in since its last yield claim.
//! 2. **Auto-bench from SELECTION, never from SAFETY** ([`ActivityLedger::selected`]): a seat idle for more than
//!    [`BENCH_WINDOWS`] complete windows is not drawn for work; it returns the window any object of its applies again. The
//!    ledger answers selection only — it exposes no weight, so no safety tally (finality 2/3, custody ≥ 2/3, a mark's > 2/3)
//!    can read a "smaller active set" through it (a source census pins that the tallies never name it).
//! 3. **Long absence unbonds without slash** ([`ActivityLedger::due_unbond`]): idle for [`UNBOND_WINDOWS`] (7 days).
//! 4. **Uptime-weighted pay** ([`uptime_split`]) and **operator-first slashing** ([`slash_split`]), both conserving.
//!
//! Borrowed shapes: Ethereum's per-epoch participation flags and inactivity response (here a clean exit, not a leak);
//! Cosmos SDK `x/slashing` downtime jailing — out of selection, never out of the bonded total until the unbond lands;
//! Polkadot's nominated proof-of-stake — the operator's own stake first in line.
//!
//! O(1): every rule is constant work per seat; `due_unbond` reads the seated set, which is bounded by the validator set.
//! O1-FOOTPRINT-REVIEWED: one [`Activity`] (three u64 words) per seated validator, removed with the seat.

use std::collections::BTreeMap;

/// Complete idle windows a seat may have before it is benched from selection (two hours of 1-hour windows).
pub const BENCH_WINDOWS: u64 = 2;
/// Complete idle windows after which a seat is unbonded without slash: 7 days of 1-hour windows.
pub const UNBOND_WINDOWS: u64 = 7 * 24;

#[cfg(test)]
thread_local! {
    /// Test seam, beside `epoch_deal_tx::TEST_EPOCH_MS`: a pin's absence window, so a two-node pin reaches the exit inside
    /// its fixture's fold-ahead cap (DB-396: 64 steps). Production always reads [`UNBOND_WINDOWS`].
    pub static TEST_UNBOND_WINDOWS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The absence window: [`UNBOND_WINDOWS`] (a test may shorten it on its own thread).
#[must_use]
pub fn unbond_windows() -> u64 {
    #[cfg(test)]
    if let Some(n) = TEST_UNBOND_WINDOWS.with(std::cell::Cell::get) {
        return n;
    }
    UNBOND_WINDOWS
}

/// One seat's activity word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Activity {
    /// The last window in which any of the seat's objects applied (the window it was seated in, before any).
    pub last: u64,
    /// Windows with at least one applied object since `since`.
    pub active: u64,
    /// The window the current pay period started in (seating, or the last claim).
    pub since: u64,
}

/// The fold's activity state: one [`Activity`] per seated custodian, a function of the chain. It lives inside the epoch-key
/// ledger (`epoch_deal_tx::EpochKeyLedger::activity`), whose hourly tick is its window clock and whose deals are its heartbeat,
/// so it rides that ledger's fold journal, snapshot and certified bundle unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivityLedger {
    /// O1-FOOTPRINT-REVIEWED: one entry per seated custodian, dropped at the tick after the seat leaves.
    seats: BTreeMap<[u8; 32], Activity>,
    /// The window the fold stands in (set at each hourly tick).
    pub now: u64,
}

impl ActivityLedger {
    /// ⭐ The hourly tick: the fold now stands in window `w`; every custodian seated now holds a word (a new seat starts
    /// active in `w`), and the word of an id no longer seated leaves.
    pub fn tick(&mut self, w: u64, seated: &[[u8; 32]]) {
        self.now = self.now.max(w);
        self.seats.retain(|id, _| seated.binary_search(id).is_ok());
        for id in seated {
            self.seat(*id, w);
        }
    }

    /// A seat lands in window `w`: it starts active (a fresh seat is selectable at once) with an empty pay period. A seat
    /// already present keeps its word — a re-bond is not a new start.
    pub fn seat(&mut self, id: [u8; 32], w: u64) {
        self.seats.entry(id).or_insert(Activity { last: w, active: 0, since: w });
    }

    /// The seat leaves (unbond, slash, absence): its word goes with it.
    pub fn unseat(&mut self, id: &[u8; 32]) {
        self.seats.remove(id);
    }

    /// One of `id`'s signed objects applied in window `w` (the window of the fold's CARRYING chain block, which is monotone
    /// along the canonical order every node folds). A window counts once; an object for a window not after the last is
    /// already counted. An unseated id has no word to move.
    pub fn observe(&mut self, id: &[u8; 32], w: u64) {
        if let Some(a) = self.seats.get_mut(id) {
            if w > a.last || (w == a.last && a.active == 0 && w >= a.since) {
                a.active = a.active.saturating_add(1);
                a.last = w;
            }
        }
    }

    /// Complete windows since the seat's last activity, judged in window `now`; `None` for an unseated id.
    #[must_use]
    pub fn idle(&self, id: &[u8; 32], now: u64) -> Option<u64> {
        self.seats.get(id).map(|a| now.saturating_sub(a.last))
    }

    /// ⭐ SELECTION ONLY: is `id` drawn for work in window `now` — epoch-key rosters, clearing committees, payout proposer
    /// rotation, prover-step ownership? Seated and idle for no more than [`BENCH_WINDOWS`] complete windows.
    #[must_use]
    pub fn selected(&self, id: &[u8; 32], now: u64) -> bool {
        self.idle(id, now).is_some_and(|i| i <= BENCH_WINDOWS)
    }

    /// The seats idle for [`UNBOND_WINDOWS`] or more complete windows at `now`, sorted: each is unbonded through the
    /// ordinary unbonding, nothing slashed.
    #[must_use]
    pub fn due_unbond(&self, now: u64) -> Vec<[u8; 32]> {
        self.seats.iter().filter(|(_, a)| now.saturating_sub(a.last) >= unbond_windows()).map(|(k, _)| *k).collect()
    }

    /// The seat's pay-period uptime at `now`: `(active windows, windows in the period)`. A period always holds at least the
    /// window it started in, so the denominator is never 0.
    #[must_use]
    pub fn uptime(&self, id: &[u8; 32], now: u64) -> Option<(u64, u64)> {
        self.seats.get(id).map(|a| {
            let windows = now.saturating_sub(a.since).saturating_add(1);
            (a.active.min(windows), windows)
        })
    }

    /// A claim at `now` closes the pay period: the next one starts in the next window with nothing counted.
    pub fn close_period(&mut self, id: &[u8; 32], now: u64) {
        if let Some(a) = self.seats.get_mut(id) {
            a.since = now.saturating_add(1);
            a.active = 0;
        }
    }

    /// The seat's word, for the snapshot and the sync bundle.
    #[must_use]
    pub fn get(&self, id: &[u8; 32]) -> Option<Activity> {
        self.seats.get(id).copied()
    }

    /// Every seat's word, sorted — what the snapshot and the sync bundle carry.
    #[must_use]
    pub fn words(&self) -> Vec<([u8; 32], Activity)> {
        self.seats.iter().map(|(k, a)| (*k, *a)).collect()
    }

    /// Install the words a certified bundle or a snapshot carried, replacing this node's own.
    pub fn adopt(&mut self, words: &[([u8; 32], Activity)]) {
        self.seats = words.iter().copied().collect();
    }
}

/// ⭐ Uptime-weighted pay: of `accrued` yield, the seat is paid `accrued × active / windows`; the rest is RETAINED in the
/// bonders' pool for the active seats. `paid + retained == accrued` — nothing minted, nothing burned. `windows == 0` pays
/// nothing (retains all), never divides by zero.
#[must_use]
pub fn uptime_split(accrued: u64, active: u64, windows: u64) -> (u64, u64) {
    if windows == 0 {
        return (0, accrued);
    }
    let paid = u128::from(accrued) * u128::from(active.min(windows)) / u128::from(windows);
    let paid = u64::try_from(paid).map_or(accrued, |p| p.min(accrued));
    (paid, accrued - paid)
}

/// What a slash is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashCause {
    /// Equivocation or epoch-key fraud: misbehaviour that loses no one's money.
    NoLoss,
    /// Reserve theft: the loss, valued in SAT at §BR-3's haircut price.
    Theft { loss_sat: u128 },
}

/// The three parts of an operator-first slash. `own_burned + delegated_burned + delegated_returned == own + delegated`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashSplit {
    /// The operator's own bond, burned.
    pub own_burned: u128,
    /// Delegated SAT burned — only for a theft's loss the operator's own bond did not cover.
    pub delegated_burned: u128,
    /// Delegated SAT that starts its ordinary 21-day return to the delegators.
    pub delegated_returned: u128,
}

/// ⭐ Operator-first slashing (§22 5): the operator's own bond is burned whole; delegated SAT is burned only for a theft's
/// loss beyond it, and the rest of the delegation returns.
#[must_use]
pub fn slash_split(own: u128, delegated: u128, cause: SlashCause) -> SlashSplit {
    let delegated_burned = match cause {
        SlashCause::NoLoss => 0,
        SlashCause::Theft { loss_sat } => loss_sat.saturating_sub(own).min(delegated),
    };
    SlashSplit { own_burned: own, delegated_burned, delegated_returned: delegated - delegated_burned }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];

    /// ⭐⭐⭐ §22 2 — a validator inactive for two complete windows is still selected; one more idle window benches it from
    /// selection; the window any object of its applies, it is selected again. Its neighbour, active throughout, never moves.
    #[test]
    fn a_validator_inactive_for_two_windows_is_not_selected_and_returns_after_one_object() {
        let mut l = ActivityLedger::default();
        l.seat(A, 10);
        l.seat(B, 10);
        assert!(l.selected(&A, 10), "a fresh seat is selectable at once");
        for w in 10..=20 {
            l.observe(&B, w);
        }
        l.observe(&A, 11);
        assert!(l.selected(&A, 13), "idle for windows 12 and 13 (13 in progress): within the bench allowance");
        assert!(!l.selected(&A, 14), "idle for three complete windows: benched from selection");
        assert!(!l.selected(&A, 20));
        l.observe(&A, 20);
        assert!(l.selected(&A, 20), "one applied object returns it in the same window");
        assert!(l.selected(&A, 22) && !l.selected(&A, 23));
        assert!(l.selected(&B, 20), "the always-active neighbour is untouched");
        assert!(!l.selected(&[0xCC; 32], 20), "an unseated id is never selected");
    }

    /// ⭐⭐⭐ §22 2 — after 168 idle windows (7 days) the seat is due to unbond, and not one window before; activity at any
    /// point restarts the count; an unseated id is never listed.
    #[test]
    fn a_validator_inactive_for_seven_days_is_due_to_unbond_and_not_a_window_before() {
        let mut l = ActivityLedger::default();
        l.seat(A, 0);
        l.seat(B, 0);
        l.observe(&A, 5);
        l.observe(&B, 5);
        assert!(l.due_unbond(5 + UNBOND_WINDOWS - 1).is_empty(), "167 idle windows is not 7 days");
        l.observe(&B, 100);
        assert_eq!(l.due_unbond(5 + UNBOND_WINDOWS), vec![A], "A reaches 168 idle windows; B was active at 100");
        assert_eq!(l.due_unbond(100 + UNBOND_WINDOWS), vec![A, B]);
        l.unseat(&A);
        assert_eq!(l.due_unbond(100 + UNBOND_WINDOWS), vec![B], "an unseated id is never listed again");
    }

    /// The hourly tick: every custodian seated now holds a word (a new one starts active), a departed one's word leaves, a
    /// returning seat keeps its record, and the clock never runs back.
    #[test]
    fn the_hourly_tick_seats_new_custodians_and_drops_departed_ones() {
        let mut l = ActivityLedger::default();
        let mut seated = vec![A, B];
        seated.sort_unstable();
        l.tick(5, &seated);
        assert!(l.get(&A).is_some() && l.get(&B).is_some() && l.now == 5);
        assert!(l.selected(&B, 5), "a new custodian is drawn at once");
        l.observe(&A, 6);
        l.tick(7, &[A]);
        assert!(l.get(&B).is_none(), "a departed custodian's word leaves");
        assert_eq!(l.get(&A).map(|w| (w.last, w.active, w.since)), Some((6, 1, 5)), "the record of a seat that stays is kept");
        l.tick(6, &[A]);
        assert_eq!(l.now, 7, "the clock never runs back");
    }

    /// A window counts once, an earlier window never re-counts, and the seating window counts when the seat signs in it.
    #[test]
    fn a_window_counts_once_toward_uptime() {
        let mut l = ActivityLedger::default();
        l.seat(A, 10);
        l.observe(&A, 10);
        l.observe(&A, 10);
        l.observe(&A, 12);
        l.observe(&A, 11); // already past: the canonical order never carries it, and it never re-counts
        l.observe(&A, 12);
        assert_eq!(l.uptime(&A, 13), Some((2, 4)), "windows 10 and 12 of 10..=13");
        l.close_period(&A, 13);
        assert_eq!(l.uptime(&A, 15), Some((0, 2)), "a claim starts a fresh period in the next window");
        l.observe(&A, 15);
        assert_eq!(l.uptime(&A, 15), Some((1, 2)));
        assert!(l.selected(&A, 15));
    }

    /// ⭐⭐⭐ §22 3 — uptime-weighted pay conserves the bonders' pool: for every accrual and uptime, paid + retained is the
    /// accrual, a full-uptime seat is paid all of it, an absent seat none, and pay never falls as uptime rises.
    #[test]
    fn uptime_weighted_yield_conserves_the_bonders_pool() {
        for accrued in [0u64, 1, 7, 999, 1_000_000, u64::MAX] {
            for windows in [0u64, 1, 3, 2190, u64::MAX] {
                let mut actives = [0u64, 1, 2, windows / 2, windows, windows.saturating_add(5)];
                actives.sort_unstable();
                let mut prev = 0;
                for active in actives {
                    let (p, r) = uptime_split(accrued, active, windows);
                    assert_eq!(u128::from(p) + u128::from(r), u128::from(accrued), "nothing minted, nothing burned");
                    assert!(p >= prev, "pay never falls as uptime rises");
                    prev = p;
                }
                if windows > 0 {
                    assert_eq!(uptime_split(accrued, windows, windows).0, accrued, "full uptime is paid in full");
                }
                assert_eq!(uptime_split(accrued, 0, windows).0, 0, "an absent seat is paid nothing");
            }
        }
        assert_eq!(uptime_split(1000, 3, 4), (750, 250));
        // a pool shared by seats of different uptime: what is paid plus what is retained is the pool
        let seats = [(400u64, 4u64), (300, 2), (300, 0)];
        let (paid, kept) = seats.iter().fold((0u64, 0u64), |(p, k), (acc, act)| {
            let (pp, kk) = uptime_split(*acc, *act, 4);
            (p + pp, k + kk)
        });
        assert_eq!((paid, kept), (550, 450));
        assert_eq!(paid + kept, 1000);
    }

    /// ⭐⭐⭐ §22 5 — equivocation and epoch-key fraud burn the operator's own bond and return every delegated SAT.
    #[test]
    fn equivocation_burns_the_operators_own_bond_and_returns_delegated_sat() {
        let s = slash_split(1_000, 9_000, SlashCause::NoLoss);
        assert_eq!(s, SlashSplit { own_burned: 1_000, delegated_burned: 0, delegated_returned: 9_000 });
        assert_eq!(slash_split(0, 5, SlashCause::NoLoss).delegated_returned, 5, "an operator with no own bond still returns it");
    }

    /// ⭐⭐⭐ §22 5 — theft burns the operator's whole own bond first; delegated SAT is burned only for the loss beyond it, and
    /// the rest of the delegation returns. Conservation for every split.
    #[test]
    fn theft_burns_delegated_sat_only_beyond_the_operators_bond() {
        let cover = slash_split(1_000, 9_000, SlashCause::Theft { loss_sat: 600 });
        assert_eq!(cover, SlashSplit { own_burned: 1_000, delegated_burned: 0, delegated_returned: 9_000 }, "own bond covers it");
        let beyond = slash_split(1_000, 9_000, SlashCause::Theft { loss_sat: 4_000 });
        assert_eq!(beyond, SlashSplit { own_burned: 1_000, delegated_burned: 3_000, delegated_returned: 6_000 });
        let all = slash_split(1_000, 9_000, SlashCause::Theft { loss_sat: u128::MAX });
        assert_eq!(all, SlashSplit { own_burned: 1_000, delegated_burned: 9_000, delegated_returned: 0 }, "capped at the delegation");
        for own in [0u128, 1, 1_000, u128::MAX / 2] {
            for del in [0u128, 1, 9_000, u128::MAX / 2] {
                for cause in [SlashCause::NoLoss, SlashCause::Theft { loss_sat: 0 }, SlashCause::Theft { loss_sat: 5_000 }, SlashCause::Theft { loss_sat: u128::MAX }] {
                    let s = slash_split(own, del, cause);
                    assert_eq!(s.own_burned + s.delegated_burned + s.delegated_returned, own + del);
                    assert_eq!(s.own_burned, own, "the operator's own bond is always first and whole");
                }
            }
        }
    }

    /// ⭐⭐⭐ §22 2 — BENCHING NEVER MOVES A SAFETY TALLY'S DENOMINATOR: the functions that compute the finality, custody and
    /// mark tallies' totals never name the activity ledger. Calibrated: a planted read is found.
    #[test]
    fn benching_never_moves_a_safety_tally_denominator() {
        const TALLY_FNS: &[&str] =
            &["fn total_bond", "fn total_finality_weight", "fn total_finality_weight_at", "fn bond_of", "fn finality_weight_of_at"];
        const ACTIVITY: &[&str] = &["ActivityLedger", "activity.", "selected(", "validator_activity"];
        fn reads(src: &str) -> Vec<String> {
            let mut hits = Vec::new();
            let lines: Vec<&str> = src.lines().collect();
            for (i, l) in lines.iter().enumerate() {
                if !TALLY_FNS.iter().any(|f| l.contains(&format!("{f}(")) || l.contains(&format!("{f}<"))) {
                    continue;
                }
                let mut depth = 0i64;
                for body in &lines[i..] {
                    depth += body.matches('{').count() as i64 - body.matches('}').count() as i64;
                    if ACTIVITY.iter().any(|a| body.split("//").next().is_some_and(|c| c.contains(a))) {
                        hits.push(format!("{} :: {}", l.trim(), body.trim()));
                    }
                    if depth <= 0 && body.contains('}') {
                        break;
                    }
                }
            }
            hits
        }
        let planted = "pub fn total_bond(&self) -> u128 {\n    self.activity.selected(&id, now);\n}\n";
        assert_eq!(reads(planted).len(), 1, "calibration: a tally reading the activity ledger is found");
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/validator.rs"))
            .unwrap_or_else(|e| panic!("cannot read validator.rs: {e}"));
        assert!(src.contains("fn total_bond("), "the census still finds the tally it guards");
        let found = reads(&src);
        assert!(found.is_empty(), "⛔ a safety tally reads the activity ledger: {found:?}");
    }
}

#[cfg(kani)]
mod kani_laws {
    /// Kani: for every accrual and uptime, the pay split conserves and pays no more than the accrual.
    #[kani::proof]
    fn uptime_split_conserves() {
        let (acc, active, windows): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let (p, r) = super::uptime_split(acc, active, windows);
        assert!(u128::from(p) + u128::from(r) == u128::from(acc));
        assert!(p <= acc);
    }

    /// Kani: for every bond, delegation and loss, the slash split conserves and the own bond is first and whole.
    #[kani::proof]
    fn slash_split_conserves() {
        let (own, del, loss): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let theft: bool = kani::any();
        let cause = if theft { super::SlashCause::Theft { loss_sat: u128::from(loss) } } else { super::SlashCause::NoLoss };
        let s = super::slash_split(u128::from(own), u128::from(del), cause);
        assert!(s.own_burned + s.delegated_burned + s.delegated_returned == u128::from(own) + u128::from(del));
        assert!(s.own_burned == u128::from(own));
        assert!(!theft || s.delegated_burned <= u128::from(loss).saturating_sub(u128::from(own)));
    }
}

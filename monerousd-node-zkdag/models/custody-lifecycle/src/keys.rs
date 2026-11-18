// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ STAGE THREE AS A MODEL — COINS FOLLOW THE LEDGERS (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3e): which
//! custodians' KEYS hold a vault's coins, when those coins are swept to the vault's current members, the weekly churn
//! with its mixing, who pays, and when a leaver's bond comes back. Written and checked BEFORE the node code, on top of
//! the seat and ledger rules in the crate root.
//!
//! THE FACTS THE RULES STAND ON (read from the node, 2026-11-11):
//!   • a Bitcoin reserve coin is locked to the k-of-n leaf of the member set that was live when it was deposited
//!     (`btc_tx::custody_leaf`), and stays under that leaf until it is spent; the payout lane keeps every leaf that
//!     holds coins in its book — so a custodian that left long ago still holds a key to old coins;
//!   • Monero has no script: one multisig wallet per member set (`xmr_custody`), and today nothing moves an old
//!     wallet's coins when the set changes (finding A-F20);
//!   • a custodian that unbonds loses its weight at once and its collateral waits out the unbonding window.
//!
//! THE RULES (one function each; the node function that will implement it is named beside it):
//!   R1  A KEY is a member set. A vault has one CURRENT key (its deposit address) and, for a while, REPLACED keys that
//!       still hold coins or whose handed-out addresses may still be paid (`ADDRESS_WINDOW`).
//!   R2  MAKE BEFORE BREAK: a vault takes a new key only at a re-key, and the old key stays a valid deposit address
//!       until the new one is the address — a deposit never waits on a key exchange.
//!   R3  A RE-KEY forms the key of the vault's members at that moment and sweeps every replaced key's coins to it.
//!       It happens (a) on the vault's weekly rotation, (b) AT ONCE when a key holds a slashed custodian, (c) when a
//!       key holds a custodian that is unbonding: at the first low-fee tick, and at ANY fee under the ceiling once two
//!       thirds of the unbonding window have passed.
//!   R4  THE RELEASE GATE: a leaver's collateral comes back only when the window has passed AND no LIVE key names it —
//!       a key of a vault whose ledgers stand moved, or the current key (or one inside its address window) of a vault
//!       that still has a member. "No key outlives its bond" is then true by construction, whatever foreign fees do;
//!       the fee rules only bound how long a leaver waits. A key of a vault that stands behind nothing and can no
//!       longer be paid holds nobody (FOUND while writing the node's gate pin: under "any alive key holds", the last
//!       custodian of a custody set that never took a deposit could never have its bond back).
//!   R5  THE WEEKLY ROTATION, a chain rule, by the node's own functions (`custody_vaults::rotations`, `mix_seats`): a
//!       vault due for its mix (a period after its last one; a vault that never mixed, on its own day) swaps
//!       `custody_vaults::MIX` members with a partner DRAWN among the settled vaults (seats swap, sizes do not change);
//!       both take their new key at once and both clocks are set — only when neither has a replaced key still alive
//!       and the budget covers both sweeps. The old keys' coins are swept on the first low-fee day after. At most
//!       ⌈vaults / 7⌉ rotations a day and twice as many rotation sweeps, the longest waiting first — so a run of high
//!       fees never ends with every vault's coins in flight on one day. (Before 2026-11-11 the partner was the next
//!       vault and re-keyed on its own day; spec §3f.2 says why the node does not build that.)
//!   R6  WHO PAYS a sweep's foreign fee: the leaver whose key it retires; the slashed bond; otherwise the rotation
//!       budget (fed by the bonders' own fee income), and for a merge or a forced re-key the vault's own members when
//!       the budget is short. Never a reserve, a pool or a user: the fee leaves custody and the same value is retired
//!       from the supply by the payer, so no vault's backing falls.
//!   R7  A MERGE and a REBALANCE move coins first (a sweep to the receiving vault's current key), then ledgers.
//!
//! THE INVARIANTS (`Chain::check`, after every event):
//!   K0  THE LEDGER FOLLOWS EVERY COIN: for every vault, the coins under its keys are exactly what its ledger stands
//!       behind.
//!   K1  NO KEY OUTLIVES ITS BOND: no key that is alive names a custodian whose collateral has been returned.
//!   K2  after any tick on which sweeps can be signed, no key that holds coins names a slashed custodian (while the
//!       vault has a member to sweep to and the key's quorum still signs).
//!   K3  no pool pays: every fee is paid by the budget, a leaver, a slashed bond or the vault's own members, and the
//!       budget never goes below zero.
//!   K4  a vault with a member always has a deposit address once it has taken a deposit.
//!   K5  at most ⌈vaults / 7⌉ scheduled rotations on any day.
//!   L1  (liveness) with no day above the fee ceiling, a leaver's collateral is back within the unbonding window plus
//!       the address window plus two days.
//!
//! WHAT IS ASSUMED, NOT PROVEN: under a third of any key's members are slashed or gone between two ticks (the
//! threshold assumption every k-of-n custody makes — past it the key no longer signs and its coins wait). The model
//! counts those cases (`Chain::unsignable`) instead of hiding them.

use crate::custody_vaults::{quorum, vault_of_seat};
use crate::{entropy, Did, World};
use std::collections::{BTreeMap, BTreeSet};

/// Days between a vault's scheduled re-keys: three inside the unbonding window.
pub const ROTATION_PERIOD: u64 = 7;
/// Days a leaver's collateral waits.
pub const UNBOND_WINDOW: u64 = 21;
/// From this many days after a leave, the re-key that retires the leaver's key goes at any fee under the ceiling.
pub const REKEY_ANY_FEE_AFTER: u64 = UNBOND_WINDOW * 2 / 3;
/// Days a replaced key's handed-out deposit addresses may still be paid and minted.
pub const ADDRESS_WINDOW: u64 = 1;
/// A sweep's foreign fee, in the model's units.
pub const SWEEP_FEE: u128 = 3;

/// A custodian's own reading of a foreign chain's fee on one day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fee {
    /// at or under the median of its own readings over the last period
    Low,
    /// above that median, under the ceiling a signer accepts (F7)
    High,
    /// above the ceiling: no sweep is signed today
    Blocked,
}

/// Who paid a sweep's fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Payer {
    Leaver,
    Slashed,
    Budget,
    Members,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub members: BTreeSet<u32>,
    pub coins: u128,
    /// the day another key became the vault's deposit address; `None` while this one is
    pub replaced_on: Option<u64>,
}

/// CALIBRATION switches. The design is every switch off; each one removes a rule so the model can be shown to go red.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Without {
    /// R4 off: a leaver's collateral returns when the window passes, whatever keys name it
    pub release_gate: bool,
    /// R3 (b) off: a key that names a slashed custodian waits for the weekly rotation like any other
    pub forced_rekey: bool,
    /// R5's daily bound off: every overdue vault rotates on the first low-fee day
    pub rotation_cap: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Chain {
    pub w: World,
    pub day: u64,
    /// vault → its keys, oldest first; the last one is the current key
    pub keys: BTreeMap<usize, Vec<Key>>,
    /// custodian → the day it left (its collateral is held)
    pub unbonding: BTreeMap<u32, u64>,
    pub released: BTreeSet<u32>,
    pub slashed: BTreeSet<u32>,
    pub budget: u128,
    pub budget_in: u128,
    pub paid_by_budget: u128,
    pub paid_by_leavers: u128,
    pub paid_by_slashed: u128,
    pub paid_by_members: u128,
    pub last_rotation: BTreeMap<usize, u64>,
    pub rotations_today: usize,
    pub rotation_sweeps_today: usize,
    pub most_rotation_sweeps_in_a_day: usize,
    pub most_rotations_in_a_day: usize,
    pub most_vaults_on_that_day: usize,
    pub sweeps: u64,
    pub merges: u64,
    pub mixes: u64,
    /// keys seen holding coins that their quorum no longer signs for (the threshold assumption, broken by slashes)
    pub unsignable: u64,
    pub longest_wait: u64,
    pub blocked_days: u64,
    pub without: Without,
}

impl Chain {
    #[must_use]
    pub fn with(n: u32) -> Self {
        Chain { w: World::with(n), ..Default::default() }
    }

    fn members_of(&self, v: usize) -> BTreeSet<u32> {
        self.w.seats.iter().filter(|(s, _)| vault_of_seat(**s) == v).map(|(_, id)| *id).collect()
    }
    fn seats_of(&self, v: usize) -> Vec<u64> {
        self.w.seats.keys().copied().filter(|s| vault_of_seat(*s) == v).collect()
    }
    /// Does a quorum of `k`'s members still sign: every member that is neither slashed nor paid out (a seated
    /// custodian, or a leaver whose collateral is still held — R4 is what keeps a leaver signing).
    fn signs(&self, k: &Key) -> bool {
        k.members.iter().filter(|id| !self.slashed.contains(id) && !self.released.contains(id)).count() >= quorum(k.members.len())
    }
    /// Can key `k` of vault `v` hold or receive coins the ledger counts? The vault's ledgers stand moved (coins may sit
    /// under any of its alive keys), or the vault has a member and the key is its current one or inside its address
    /// window (a deposit can still be minted to it).
    fn live(&self, v: usize, k: &Key) -> bool {
        self.w.moved.contains(&v) || (self.w.members(v) > 0 && k.replaced_on.is_none_or(|d| d + ADDRESS_WINDOW >= self.day))
    }
    /// R4's rule (`PegLedger::vault_key_holds`): a custodian is HELD while a key that names it is live. A key of a vault
    /// that stands behind nothing and can no longer be paid — replaced with its window passed, or of a vault with no
    /// member left — holds nobody: there is provably nothing under it, and such a vault could never retire it.
    #[must_use]
    pub fn holds(&self, id: u32) -> bool {
        self.keys.iter().any(|(v, ks)| ks.iter().any(|k| k.members.contains(&id) && self.live(*v, k)))
    }
    #[must_use]
    pub fn coins(&self, v: usize) -> u128 {
        self.keys.get(&v).map_or(0, |ks| ks.iter().map(|k| k.coins).sum())
    }

    /// R1/R2 — the vault's current key; its first one is formed from its members when it is first needed (a key
    /// exchange costs no foreign fee).
    fn current(&mut self, v: usize) -> Option<&mut Key> {
        if !self.keys.get(&v).and_then(|ks| ks.last()).is_some_and(|k| k.replaced_on.is_none()) {
            let members = self.members_of(v);
            if members.is_empty() {
                return None;
            }
            self.keys.entry(v).or_default().push(Key { members, coins: 0, replaced_on: None });
        }
        self.keys.get_mut(&v).and_then(|ks| ks.last_mut())
    }

    // ── events ──────────────────────────────────────────────────────────────────────────────────────────────────

    /// A bond. A vault that has a member and no current key forms one at once (R2: a key exchange costs no foreign
    /// fee) — a split's new vault, or a vault whose every earlier member was taken out.
    pub fn bond(&mut self, e: &[u8; 32]) -> Did {
        let did = self.w.bond(e);
        if let Did::Bonded { seat, .. } = did {
            let _ = self.current(vault_of_seat(seat));
        }
        did
    }

    /// A leave (`unbond_tx` → `Node::release_matured_bond`): the weight goes now, the collateral is held (R4).
    pub fn leave(&mut self, seat: u64) -> Did {
        let id = self.w.seats.get(&seat).copied();
        let did = self.w.leave(seat);
        if let (Did::Left, Some(id)) = (&did, id) {
            self.unbonding.insert(id, self.day);
        }
        did
    }

    /// A slash: the bond is gone at once, the key it holds is not — R3 (b) retires it at the next tick.
    pub fn gone(&mut self, seat: u64) -> Did {
        let id = self.w.seats.get(&seat).copied();
        let did = self.w.gone(seat);
        if let (Did::Left, Some(id)) = (&did, id) {
            self.slashed.insert(id);
        }
        did
    }

    /// A deposit routed by the chain: the coin lands under the routed vault's current key.
    pub fn deposit(&mut self, amount: u128, nonce: u64) -> Did {
        let Some(v) = self.w.route(nonce) else { return Did::Nothing };
        if self.current(v).is_none() {
            return Did::Nothing;
        }
        let did = self.w.deposit(amount, nonce);
        if let Did::Deposited { vault, .. } = did {
            self.current(vault).expect("the routed vault has a key").coins += amount;
        }
        did
    }

    /// A payment to an address that was handed out earlier: the vault's CURRENT address although the router no
    /// longer sends deposits there (`replaced: false`), or a REPLACED key's address inside its window. Minted on that
    /// vault's ledger like any deposit; the coin sits under the key it was paid to. Past the window the node mints
    /// nothing (a Bitcoin deposit's own refund leaf returns it; a Monero address has expired with its swap).
    pub fn pay_handed_out_address(&mut self, vault: usize, replaced: bool, amount: u128) -> Did {
        if self.w.members(vault) == 0 {
            return Did::Nothing;
        }
        let day = self.day;
        let i = if replaced {
            self.keys.get(&vault).and_then(|ks| ks.iter().position(|k| k.replaced_on.is_some_and(|d| d + ADDRESS_WINDOW >= day)))
        } else {
            self.keys.get(&vault).and_then(|ks| ks.len().checked_sub(1))
        };
        let Some(i) = i else { return Did::Nothing };
        *self.w.held.entry(vault).or_default() += amount;
        self.w.moved.insert(vault);
        self.w.deposited += amount;
        self.keys.get_mut(&vault).expect("keys")[i].coins += amount;
        Did::Deposited { vault, alone: false }
    }

    /// A cash-out paid by `vault`: from coins under keys a quorum still signs for, the current key's first.
    pub fn withdraw(&mut self, vault: usize, amount: u128) -> Did {
        if amount == 0 || self.w.held(vault) < amount || self.w.members(vault) == 0 {
            return Did::Nothing;
        }
        let usable: u128 = self.keys.get(&vault).map_or(0, |ks| ks.iter().filter(|k| self.signs(k)).map(|k| k.coins).sum());
        if usable < amount {
            return Did::Refused("the vault's coins sit under a key no quorum signs for: the cash-out is offered to another vault");
        }
        let did = self.w.withdraw(vault, amount);
        let signing: Vec<bool> = self.keys[&vault].iter().map(|k| self.signs(k)).collect();
        let mut left = amount;
        for (i, k) in self.keys.get_mut(&vault).expect("keys").iter_mut().enumerate().rev() {
            if signing[i] {
                let take = left.min(k.coins);
                k.coins -= take;
                left -= take;
            }
        }
        assert_eq!(left, 0);
        did
    }

    /// R6 — who pays for sweeping key `k`, and whether it can pay. The budget pays only while it covers twice the fee.
    fn payer(&self, k: &Key, or_members: bool) -> Option<Payer> {
        if k.members.iter().any(|id| self.unbonding.contains_key(id)) {
            Some(Payer::Leaver)
        } else if k.members.iter().any(|id| self.slashed.contains(id)) {
            Some(Payer::Slashed)
        } else if self.budget >= 2 * SWEEP_FEE {
            Some(Payer::Budget)
        } else if or_members {
            Some(Payer::Members)
        } else {
            None
        }
    }

    /// THE SWEEP — the one primitive (R3, R7): move `amount` (or all) of the coins under `from`'s key `i` to `into`'s
    /// current key. The fee comes out of the coins moved; the payer retires the same value from the supply, booked on
    /// the receiving ledger (`Class::ReserveCost`), so K0 holds on both sides. `false`: the key's quorum does not
    /// sign, or nobody may pay — nothing moved.
    fn sweep(&mut self, from: usize, i: usize, into: usize, amount: Option<u128>, or_members: bool) -> bool {
        let k = self.keys[&from][i].clone();
        let amount = amount.unwrap_or(k.coins).min(k.coins);
        if amount == 0 {
            return true;
        }
        if !self.signs(&k) {
            return false;
        }
        let Some(payer) = self.payer(&k, or_members) else { return false };
        if self.current(into).is_none() {
            return false;
        }
        let fee = SWEEP_FEE.min(amount);
        self.keys.get_mut(&from).expect("keys")[i].coins -= amount;
        self.current(into).expect("checked").coins += amount - fee;
        // the ledger follows: the fee left custody, booked on the ledger that received the coins (a merge or a
        // rebalance has already moved `amount` between the two ledgers — see the callers)
        *self.w.held.get_mut(&into).expect("the receiving vault's ledger stands behind the coins") -= fee;
        self.w.retired += fee;
        match payer {
            Payer::Leaver => self.paid_by_leavers += fee,
            Payer::Slashed => self.paid_by_slashed += fee,
            Payer::Members => self.paid_by_members += fee,
            Payer::Budget => {
                self.budget -= fee;
                self.paid_by_budget += fee;
            }
        }
        self.sweeps += 1;
        true
    }

    /// R7 — A MERGE: the coins first (every key of the retiring vault swept to the receiving vault's current key),
    /// then the ledgers (`Class::VaultMerge`). Refused whole when a key's quorum does not sign.
    pub fn merge(&mut self, from: usize) -> Did {
        let Some(into) = self.w.merge_target(from) else { return self.w.merge(from) };
        let m = self.w.members(from);
        if m == 0 || m > crate::custody_vaults::VAULT_MIN || !self.w.moved.contains(&from) {
            return self.w.merge(from); // refused by the ledger rule, for its own reason
        }
        let ks = self.keys.get(&from).cloned().unwrap_or_default();
        if ks.iter().any(|k| k.coins > 0 && !self.signs(k)) {
            return Did::Refused("a key of the retiring vault no longer signs: its coins cannot follow the ledgers");
        }
        if self.current(into).is_none() {
            return Did::Refused("the receiving vault has no member to hold a key");
        }
        let did = self.w.merge(from);
        assert!(matches!(did, Did::Merged { .. }));
        for i in 0..ks.len() {
            assert!(self.sweep(from, i, into, None, true), "a merge's sweep is always paid (the vault's own members when the budget is short)");
        }
        did
    }

    /// R7 — A REBALANCE: coins first. Refused whole while any key that holds coins does not sign.
    pub fn rebalance(&mut self) -> Did {
        if self.keys.values().flatten().any(|k| k.coins > 0 && !self.signs(k)) {
            return Did::Refused("a key that holds coins no longer signs: nothing is rebalanced over it");
        }
        let did = self.w.rebalance();
        for (v, u, take) in self.w.last_moves.clone() {
            let mut left = take;
            let n = self.keys.get(&v).map_or(0, Vec::len);
            for i in (0..n).rev() {
                let part = left.min(self.keys[&v][i].coins);
                if part > 0 {
                    assert!(self.sweep(v, i, u, Some(part), true), "a rebalance's sweep is always paid");
                    left -= part;
                }
            }
            assert_eq!(left, 0, "K0 before the rebalance: the giving vault held the coins its ledger said");
        }
        did
    }

    /// R2 — vault `v` TAKES THE KEY OF ITS MEMBERS as they are now (a key exchange: no foreign fee). The key it had
    /// stays a valid address for its window and keeps its coins until they are swept.
    fn form(&mut self, v: usize) -> bool {
        let members = self.members_of(v);
        if members.is_empty() {
            return false;
        }
        let day = self.day;
        let ks = self.keys.entry(v).or_default();
        if ks.last().map_or(true, |k| k.replaced_on.is_some() || k.members != members) {
            if let Some(k) = ks.last_mut() {
                if k.replaced_on.is_none() {
                    k.replaced_on = Some(day);
                }
            }
            ks.push(Key { members, coins: 0, replaced_on: None });
        }
        true
    }

    /// R3 — RE-KEY vault `v` at once (a slashed or a leaving key holder): its members' key becomes the address
    /// and every replaced key's coins are swept to it. Returns how many keys were swept.
    fn rekey(&mut self, v: usize, or_members: bool) -> usize {
        if !self.form(v) {
            return 0;
        }
        let mut swept = 0;
        for i in 0..self.keys[&v].len() - 1 {
            if self.keys[&v][i].coins > 0 && self.sweep(v, i, v, None, or_members) {
                swept += 1;
            }
        }
        swept
    }

    /// R5 — the mixing: `custody_vaults::MIX` seats of `v` and of its drawn partner swap their custodians, by the
    /// node's own draw (`custody_vaults::mix_seats`).
    fn mix(&mut self, v: usize, p: usize) {
        let e = entropy(0x3317 ^ self.day, v as u64);
        for (x, y) in crate::custody_vaults::mix_seats(&self.seats_of(v), &self.seats_of(p), &e) {
            let (ix, iy) = (self.w.seats[&x], self.w.seats[&y]);
            self.w.seats.insert(x, iy);
            self.w.seats.insert(y, ix);
            self.mixes += 1;
        }
    }

    /// ONE DAY of chain time: the budget takes its slice of the bonders' income; the scheduled rotations (R5); the
    /// re-keys owed for a slashed or a leaving key holder (R3 b, c); keys that hold nothing and whose window passed
    /// retire; collateral whose window passed and whose keys are all retired comes back (R4).
    pub fn tick(&mut self, fee: Fee, income: u128) {
        self.day += 1;
        self.budget += income;
        self.budget_in += income;
        self.rotations_today = 0;
        if fee == Fee::Blocked {
            self.blocked_days += 1;
        } else {
            let seated: Vec<usize> = self.w.vaults().into_iter().filter(|v| self.w.members(*v) > 0).collect();
            // a vault that has no key yet forms one (free): its deposit address
            for v in &seated {
                let _ = self.current(*v);
            }
            // R3 (b): a key that names a slashed custodian — at once, at any fee under the ceiling
            // R3 (c): a key that names a leaver — on a low-fee day, or at any fee once two thirds of the window passed
            for v in &seated {
                let day = self.day;
                let owed = self.keys.get(v).is_some_and(|ks| {
                    ks.iter().any(|k| {
                        let slashed = !self.without.forced_rekey && k.members.iter().any(|id| self.slashed.contains(id));
                        let leaver_due = k.members.iter().filter_map(|id| self.unbonding.get(id)).any(|left| fee == Fee::Low || day >= left + REKEY_ANY_FEE_AFTER);
                        (k.replaced_on.is_none() || k.coins > 0) && (slashed || leaver_due)
                    })
                });
                if owed {
                    self.rekey(*v, true);
                }
            }
            // R8: A MERGE THAT IS DUE IS DONE (`Node::vault_merge_due`, the merge lane): a vault at half strength or
            // under whose ledgers stand moved hands them to the vault that outranks it — before more of its members
            // can be slashed out from under its coins
            for v in &seated {
                if self.w.members(*v) <= crate::custody_vaults::VAULT_MIN && self.w.moved.contains(v) && self.w.merge_target(*v).is_some() {
                    if matches!(self.merge(*v), Did::Merged { .. }) {
                        self.merges += 1;
                    }
                }
            }
        }
        // R5: THE SCHEDULED ROTATIONS — a chain rule, whatever today's fee (a seat swap and a key exchange cost no
        // foreign fee): the longest overdue first, at most ⌈vaults / 7⌉ a day, and only for a vault whose earlier
        // rotation is finished — neither it nor its partner still has a replaced key alive — and whose sweep the
        // budget covers. The vault swaps members with a drawn partner and both take their new keys at once (R2: each old
        // key stays a valid address for its window).
        {
            let seated: Vec<usize> = self.w.vaults().into_iter().filter(|v| self.w.members(*v) > 0).collect();
            let bound = seated.len().div_ceil(ROTATION_PERIOD as usize);
            let cap = if self.without.rotation_cap { usize::MAX } else { bound };
            // what the CHAIN can see: a replaced key that is still alive (not yet retired) — it may hold coins or still be paid
            let unswept = |c: &Chain, v: usize| c.keys.get(&v).is_some_and(|ks| ks.iter().any(|k| k.replaced_on.is_some()));
            // AS THE NODE BUILDS IT (spec §3f.2), BY THE NODE'S OWN FUNCTIONS (`custody_vaults::rotations`, `mix_seats`,
            // compiled here by path): the partner is DRAWN among the settled vaults, re-keys at once with the initiator
            // (the node's take rule re-keys a vault whose key names a custodian seated elsewhere), and both vaults'
            // clocks are set — so a vault re-keys about once a period, as initiator or as partner. Time is the day.
            let turns: Vec<crate::custody_vaults::VaultTurn> = seated
                .iter()
                .map(|v| crate::custody_vaults::VaultTurn { vault: *v, mixed: self.last_rotation.get(v).copied().unwrap_or(0), settled: !unswept(self, *v) })
                .collect();
            let e = entropy(0x9a27 ^ self.day, 0);
            let pairs = crate::custody_vaults::rotations_within(&turns, self.day, ROTATION_PERIOD, &e, if cap == usize::MAX { usize::MAX } else { 2 * cap });
            for (v, p) in pairs {
                let owed = u128::from(self.coins(v) > 0) + u128::from(self.coins(p) > 0);
                if self.budget < 2 * SWEEP_FEE * owed {
                    continue; // the budget does not cover the sweeps it would owe: both stay due, nothing else pays
                }
                self.mix(v, p);
                self.form(v);
                self.form(p);
                self.last_rotation.insert(v, self.day);
                self.last_rotation.insert(p, self.day);
                self.rotations_today += 1;
            }
            if self.rotations_today > self.most_rotations_in_a_day {
                self.most_rotations_in_a_day = self.rotations_today;
                self.most_vaults_on_that_day = seated.len();
            }
            assert!(self.without.rotation_cap || self.rotations_today <= bound, "K5: {} scheduled rotations in one day over {} vaults", self.rotations_today, seated.len());
            // R3 (a): THE ROTATION'S SWEEPS — on a low-fee day, paid by the budget, the longest-replaced key first and
            // at most ⌈vaults / 7⌉ a day, so a run of high fees never ends with every vault's coins in flight at once
            self.rotation_sweeps_today = 0;
            if fee == Fee::Low {
                let mut waiting: Vec<(u64, usize, usize)> = Vec::new();
                for v in &seated {
                    for (i, k) in self.keys.get(v).map_or(&[][..], |ks| &ks[..]).iter().enumerate() {
                        if let (Some(d), true) = (k.replaced_on, k.coins > 0) {
                            waiting.push((d, *v, i));
                        }
                    }
                }
                waiting.sort_unstable();
                for (_, v, i) in waiting {
                    // a rotation re-keys two vaults, so its daily bound on sweeps is two per pair
                    if self.rotation_sweeps_today >= cap.saturating_mul(2) {
                        break;
                    }
                    if self.sweep(v, i, v, None, false) {
                        self.rotation_sweeps_today += 1;
                    }
                }
                self.most_rotation_sweeps_in_a_day = self.most_rotation_sweeps_in_a_day.max(self.rotation_sweeps_today);
            }
        }
        // a replaced key that holds nothing, past its address window, is retired
        let day = self.day;
        // (`Class::VaultKey` retire: its vault's own members state it — so a vault whose ledgers moved and that has no
        // member left retires nothing; a vault that stands behind nothing needs no statement, its dead rows just go)
        let w = &self.w;
        for (v, ks) in &mut self.keys {
            let can = w.members(*v) > 0 || !w.moved.contains(v);
            ks.retain(|k| !(can && k.coins == 0 && k.replaced_on.is_some_and(|d| d + ADDRESS_WINDOW < day)));
        }
        // a vault with no member keeps no CURRENT key (nobody is left to hold one); one that holds coins stays, replaced
        for (v, ks) in &mut self.keys {
            if self.w.seats.keys().all(|s| vault_of_seat(*s) != *v) {
                if let Some(k) = ks.last_mut() {
                    if k.replaced_on.is_none() {
                        k.replaced_on = Some(day);
                    }
                }
            }
        }
        // R4: the release gate (`PegLedger::vault_key_holds`)
        let due: Vec<u32> = self.unbonding.iter().filter(|(id, left)| day >= **left + UNBOND_WINDOW && (self.without.release_gate || !self.holds(**id))).map(|(id, _)| *id).collect();
        for id in due {
            let left = self.unbonding.remove(&id).expect("due");
            self.longest_wait = self.longest_wait.max(day - left);
            self.released.insert(id);
        }
    }

    /// K0 … K4 (K5 is asserted where rotations are counted; L1 where the walk knows no day was blocked).
    pub fn check(&mut self) {
        self.w.check();
        let vaults: BTreeSet<usize> = self.w.vaults().into_iter().chain(self.keys.keys().copied()).collect();
        for v in &vaults {
            assert_eq!(self.coins(*v), self.w.held(*v), "K0: vault {v}'s keys hold {} and its ledger stands behind {}", self.coins(*v), self.w.held(*v));
        }
        for (v, ks) in &self.keys {
            for k in ks {
                // K1 speaks of keys that hold coins or can still be paid (a dead row waiting to be dropped names nobody's risk)
                if !(k.coins > 0 || self.live(*v, k)) {
                    continue;
                }
                if let Some(id) = k.members.iter().find(|id| self.released.contains(id)) {
                    panic!("K1: a key of vault {v} (coins {}, replaced {:?}) names custodian {id}, whose collateral was returned", k.coins, k.replaced_on);
                }
            }
            if self.w.members(*v) > 0 && self.w.moved.contains(v) {
                assert!(ks.last().is_some_and(|k| k.replaced_on.is_none()), "K4: vault {v} has members and moved ledgers and no deposit address");
            }
        }
        assert_eq!(self.budget_in, self.budget + self.paid_by_budget, "K3: the budget's books do not balance");
        assert_eq!(self.w.retired, self.paid_by_budget + self.paid_by_leavers + self.paid_by_slashed + self.paid_by_members, "K3: a fee was paid by nobody the rules name");
        let unsignable = self.keys.values().flatten().filter(|k| k.coins > 0 && !self.signs(k)).count() as u64;
        self.unsignable += unsignable;
    }

    /// K2, asked right after a tick on which sweeps could be signed.
    pub fn check_after_open_tick(&self) {
        for (v, ks) in &self.keys {
            if self.w.members(*v) == 0 {
                continue;
            }
            for k in ks {
                if k.coins > 0 && self.signs(k) {
                    assert!(!k.members.iter().any(|id| self.slashed.contains(id)), "K2: a key of vault {v} still holds {} with a slashed custodian's key in it after a tick", k.coins);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Ev {
        Bond,
        Leave(usize),
        Gone(usize),
        Deposit(u128, u64),
        /// a payment to a handed-out address of the k-th vault: its current one, or a replaced one in its window
        Pay(usize, bool),
        Withdraw(usize, u128),
        Merge(usize),
        Rebalance,
        Days(u64, Fee, u128),
    }

    fn kth(c: &Chain, k: usize) -> Option<usize> {
        let v = c.w.vaults();
        (!v.is_empty()).then(|| v[k % v.len()])
    }
    fn lowest(c: &Chain, v: usize) -> Option<u64> {
        c.w.seats.keys().copied().find(|s| vault_of_seat(*s) == v)
    }

    fn step(c: &mut Chain, ev: Ev, n: u64) {
        match ev {
            Ev::Bond => {
                c.bond(&entropy(0xe1, n));
            }
            Ev::Leave(k) => {
                if let Some(s) = kth(c, k).and_then(|v| lowest(c, v)) {
                    c.leave(s);
                }
            }
            Ev::Gone(k) => {
                if let Some(s) = kth(c, k).and_then(|v| lowest(c, v)) {
                    c.gone(s);
                }
            }
            Ev::Deposit(a, nonce) => {
                c.deposit(a, nonce);
            }
            Ev::Pay(k, replaced) => {
                if let Some(v) = kth(c, k) {
                    c.pay_handed_out_address(v, replaced, 700);
                }
            }
            Ev::Withdraw(k, a) => {
                if let Some(v) = kth(c, k) {
                    c.withdraw(v, a);
                }
            }
            Ev::Merge(k) => {
                if let Some(v) = kth(c, k) {
                    c.merge(v);
                }
            }
            Ev::Rebalance => {
                c.rebalance();
            }
            Ev::Days(d, fee, income) => {
                for _ in 0..d {
                    c.tick(fee, income);
                    c.check();
                    if fee != Fee::Blocked {
                        c.check_after_open_tick();
                    }
                }
            }
        }
        c.check();
    }

    const ALPHABET: [Ev; 15] = [
        Ev::Bond,
        Ev::Leave(0),
        Ev::Leave(1),
        Ev::Gone(0),
        Ev::Gone(1),
        Ev::Deposit(1_000, 0),
        Ev::Deposit(40_000, 1),
        Ev::Pay(1, true),
        Ev::Pay(0, false),
        Ev::Withdraw(0, 500),
        Ev::Merge(0),
        Ev::Rebalance,
        Ev::Days(1, Fee::Low, 10),
        Ev::Days(8, Fee::High, 0),
        Ev::Days(22, Fee::Blocked, 0),
    ];

    fn every_sequence(base: &Chain, len: usize, f: &mut dyn FnMut(&[Ev])) {
        let mut idx = vec![0usize; len];
        loop {
            let evs: Vec<Ev> = idx.iter().map(|i| ALPHABET[*i]).collect();
            let mut c = base.clone();
            for (n, ev) in evs.iter().enumerate() {
                step(&mut c, *ev, n as u64);
            }
            f(&evs);
            let mut k = 0;
            while k < len {
                idx[k] += 1;
                if idx[k] < ALPHABET.len() {
                    break;
                }
                idx[k] = 0;
                k += 1;
            }
            if k == len {
                break;
            }
        }
    }

    /// ⭐ EVERY SEQUENCE of five events from four starting sets (2, 17, 33 and 49 custodians): 15^5 = 759,375 each,
    /// K0 to K4 after every event and every day, K2 after every day sweeps could be signed, K5 on every rotation day.
    #[test]
    fn every_sequence_of_five_events_keeps_coins_keys_and_bonds_together() {
        let mut sequences = 0u64;
        for start in [2u32, 17, 33, 49] {
            let mut base = Chain::with(start);
            base.check();
            every_sequence(&base, 5, &mut |_| sequences += 1);
        }
        eprintln!("[model/keys] {sequences} sequences of five events, every invariant held");
        assert_eq!(sequences, 4 * 15u64.pow(5));
    }

    /// Long walks at four sizes up to a thousand custodians (3,000 days each; 400 at a thousand) of bonds, leaves,
    /// slashes (only while every key that names the custodian keeps its quorum: the threshold assumption), deposits,
    /// late payments, cash-outs, merges, rebalances and
    /// fee weather with no day above the ceiling — so L1 is asserted: every leaver is paid back inside the window
    /// plus the address window plus two days. Prints what a build will be held to.
    #[test]
    fn long_walks_at_four_sizes_keep_every_invariant_and_every_leaver_is_paid_back_in_time() {
        for (walk, start, days) in [(1u64, 5u32, 3_000u64), (2, 40, 3_000), (3, 160, 3_000), (4, 1_000, 400)] {
            let mut c = Chain::with(start);
            let mut slashed_today: BTreeSet<usize> = BTreeSet::new();
            let mut events = 0u64;
            for n in 0..days {
                // a day's events
                for j in 0..12u64 {
                    let e = entropy(walk << 32 | n, j);
                    let pick = u64::from_le_bytes(e[..8].try_into().unwrap());
                    let seats: Vec<u64> = c.w.seats.keys().copied().collect();
                    let any_seat = (!seats.is_empty()).then(|| seats[(pick >> 8) as usize % seats.len().max(1)]);
                    match pick % 20 {
                        0..=2 => step(&mut c, Ev::Bond, n * 100 + j),
                        3..=4 => {
                            if let Some(s) = any_seat {
                                c.leave(s);
                                c.check();
                            }
                        }
                        5 => {
                            // THE THRESHOLD ASSUMPTION, exactly: a slash is drawn only while every key that names the
                            // custodian keeps its quorum without it (under a third of a key lost over the key's life)
                            if let Some(s) = any_seat {
                                let id = c.w.seats[&s];
                                let keeps = c.keys.values().flatten().filter(|k| k.members.contains(&id)).all(|k| {
                                    k.members.iter().filter(|m| **m != id && !c.slashed.contains(m) && !c.released.contains(m)).count() >= quorum(k.members.len())
                                });
                                if keeps && slashed_today.insert(vault_of_seat(s)) {
                                    c.gone(s);
                                    c.check();
                                }
                            }
                        }
                        6..=10 => step(&mut c, Ev::Deposit(u128::from(1 + (pick >> 20) % 30_000), pick >> 40), n),
                        11 => step(&mut c, Ev::Pay((pick >> 16) as usize, pick >> 63 == 1), n),
                        12..=15 => step(&mut c, Ev::Withdraw((pick >> 16) as usize, u128::from(1 + (pick >> 20) % 5_000)), n),
                        16..=17 => step(&mut c, Ev::Merge((pick >> 16) as usize), n),
                        _ => step(&mut c, Ev::Rebalance, n),
                    }
                    events += 1;
                }
                // the day turns: fee weather in runs (a week of high fees now and then), income most days
                let e = entropy(walk ^ 0xfee, n / 5);
                let fee = if e[0] % 4 == 0 { Fee::High } else { Fee::Low };
                // the budget's slice of the bonders' income grows with the network: about one sweep per vault per day
                let income = u128::from(e[1] % 3) * SWEEP_FEE * c.w.vaults().len() as u128;
                step(&mut c, Ev::Days(1, fee, income), n);
                slashed_today.clear();
                for (id, left) in &c.unbonding {
                    assert!(c.day - left <= UNBOND_WINDOW + ADDRESS_WINDOW + 2, "L1: custodian {id} left on day {left} and is still waiting on day {}", c.day);
                }
            }
            assert_eq!(c.unsignable, 0, "with never two slashes in one vault on one day, no key ever lost its quorum");
            eprintln!(
                "[model/keys] start {start}: {events} events over {} days, {} custodians and {} vaults at the end; {} merges; most rotation sweeps in a day {}; {} sweeps ({} by the budget, {} by leavers, {} by slashed bonds, {} by members), {} seats mixed, most scheduled rotations in a day {} (of {} vaults), longest wait for collateral {} days",
                c.day,
                c.w.seats.len(),
                c.w.vaults().len(),
                c.merges,
                c.most_rotation_sweeps_in_a_day,
                c.sweeps,
                c.paid_by_budget / SWEEP_FEE,
                c.paid_by_leavers / SWEEP_FEE,
                c.paid_by_slashed / SWEEP_FEE,
                c.paid_by_members / SWEEP_FEE,
                c.mixes,
                c.most_rotations_in_a_day,
                c.most_vaults_on_that_day,
                c.longest_wait
            );
        }
    }

    fn goes_red(without: Without, start: u32, len: usize) -> bool {
        std::panic::catch_unwind(|| {
            let mut base = Chain::with(start);
            base.without = without;
            every_sequence(&base, len, &mut |_| {});
        })
        .is_err()
    }

    /// CALIBRATION — the model can go red on each rule it claims to need. Without the release gate (R4) a leaver is
    /// paid back while its key still holds the vault's coins; without the forced re-key (R3 b) a slashed custodian's
    /// key holds coins past a tick. With every rule on, the same searches are green (the test above).
    #[test]
    fn without_the_release_gate_or_the_forced_rekey_the_search_goes_red() {
        assert!(goes_red(Without { release_gate: true, ..Without::default() }, 17, 3), "CALIBRATION: with no release gate the search must find a key that outlived its bond (deposit, leave, three weeks above the fee ceiling)");
        assert!(goes_red(Without { forced_rekey: true, ..Without::default() }, 17, 3), "CALIBRATION: with no forced re-key the search must find a slashed custodian's key still holding coins after a tick");
        assert!(!goes_red(Without::default(), 17, 3), "…and with every rule on, the same search is green");
    }

    /// R5's daily bound, measured both ways: every vault holds coins and two weeks of high fees pass, so every vault has
    /// rotated once and waits for a low-fee day to bring its coins home. With the bound, the first low-fee day sees
    /// ⌈vaults / 7⌉ sweeps; without it, most vaults' coins are in flight on the same day.
    // TWO-PARTY-REVIEWED: a model of the rules has no endpoint — one `Chain` value is the whole world. The node is held to
    // these rules by its own pins, each across two parties (`node::vault_pins`, `peg::tests`).
    #[test]
    fn a_fortnight_of_high_fees_does_not_end_with_every_vaults_coins_in_flight_on_one_day() {
        let run = |without: Without| -> (usize, usize, usize) {
            let mut c = Chain::with(400);
            c.without = without;
            let vaults = c.w.vaults().len();
            for v in c.w.vaults() {
                let _ = c.current(v); // its first key: its address
                assert!(matches!(c.pay_handed_out_address(v, false, 1_000), Did::Deposited { .. }));
            }
            c.check();
            let mut most_rotations = 0;
            for _ in 0..14 {
                c.tick(Fee::High, 500);
                c.check();
                most_rotations = most_rotations.max(c.rotations_today);
            }
            c.tick(Fee::Low, 500);
            c.check();
            (c.rotation_sweeps_today, most_rotations, vaults)
        };
        let (bounded, rotations, vaults) = run(Without::default());
        let (unbounded, rotations_unbounded, _) = run(Without { rotation_cap: true, ..Without::default() });
        eprintln!("[model/keys] {vaults} vaults, each holding coins, a fortnight of high fees: {bounded} sweep on the first low-fee day with the bound, {unbounded} without it (most rotations in a day: {rotations} with, {rotations_unbounded} without)");
        assert!(bounded <= 2 * vaults.div_ceil(7) && rotations <= vaults.div_ceil(7), "the bound spreads the rotations and their sweeps (two vaults re-key per rotation)");
        assert!(unbounded > vaults / 2, "CALIBRATION: without the bound most vaults sweep on the same day");
    }
}

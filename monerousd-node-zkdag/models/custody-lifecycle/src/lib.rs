// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ THE CUSTODY VAULT LIFECYCLE, AS A MODEL — THE QUICK PROOF OF THE DESIGN (user 2026-11-11: "everyone is stuck waiting on
//! pins, and builds … Is there no quick way to prove that our design is actually secure?").
//!
//! WHAT THIS IS. The rules that decide where a custodian sits, who may leave, which vault a deposit goes to, who signs
//! it, when a vault merges and when its holdings are rebalanced are a small state machine. Whether those RULES are safe
//! does not depend on the node, the prover or the wire: it can be checked on the rules alone. This crate holds them as
//! one `World` with one function per event, compiles the chain's REAL seat rules (`src/custody_vaults.rs`, included by
//! path, not copied), and checks the invariants below over EVERY sequence of events up to a fixed length from several
//! starting sets, and over long random walks. It builds in seconds and runs in seconds, so a rule is refuted before any
//! node code is written for it. MEASURED 2026-11-11: one pin run of the node crate cost 9 to 23 minutes of build for 7 to
//! 70 seconds of test (43 builds, 6.3 h, across all lanes in half a day).
//!
//! WHAT THIS IS NOT. A proof about the implementation. The node is held to these rules by its own pins (two parties,
//! what the peer holds) and by real-node attack rows (AGENTS.md §7, F6 / F7). A rule here that the node does not follow
//! is a bug the pins find; a rule here that is unsafe is found HERE, in seconds, before it is built.
//!
//! THE INVARIANTS (each a `check` every event must leave true):
//!   I1  every custodian sits on one seat; no vault holds more than sixteen.
//!   I2  a bond changes one vault, or exactly two when a full vault splits; a newcomer never joins a vault of fewer than
//!       eight while a vault of eight exists.
//!   I3  CONSERVATION: what the vaults stand behind is what was deposited less what was withdrawn — a merge and a
//!       rebalance move it, never make or lose it.
//!   I4  a vault's quorum signs a deposit ALONE only when the vault holds eight members and stays inside its bound.
//!   I5  a deposit is never refused, and it goes to a vault of more than eight members whenever one exists.
//!   I6  NOBODY WALKS AWAY FROM A LEDGER: by leaving alone (no slash, no absence), a vault whose ledgers stand moved
//!       never falls under eight members while a vault that outranks it could take them, and never to zero at all.
//!   I7  a merge moves a vault's whole holding into a vault that OUTRANKS it (more members; the lower index among
//!       equals) and leaves the first on its genesis ledgers; it is taken only out of a vault of eight or fewer. So
//!       ledgers move toward the strongest vault and stop: two thin vaults never hand them back and forth.
//!   I8  THE BOUND IS TRANSIENT: after a rebalance no vault stands past its bound while a vault of eight has room.
//!   I9  a custodian that wants to leave a thin vault can: merge, then leave.
//! The rules read "ledgers MOVED" (off their genesis pairs), as the node must: a ledger's value is hidden, so the chain
//! cannot see that everything was cashed out. STAGE THREE — which custodians' keys hold a vault's coins, the sweeps,
//! the weekly churn, who pays and when a leaver's bond comes back — is `keys.rs` (invariants K0–K5, L1), on top of this.
//!
//! BORROWED: TLA+ / TLC and Jepsen-style model checking (state a protocol as transitions and invariants and explore
//! it mechanically: Lamport; used for Paxos, Raft and Tendermint before their code); bounded exhaustive testing
//! (SmallCheck: every case up to a size). cons: a model is a second statement of the rules — it is kept honest by
//! including the real seat rules by path and by naming, beside each event, the node function that implements it.

#[allow(dead_code)]
#[path = "../../../src/custody_vaults.rs"]
pub mod custody_vaults;

use custody_vaults::{draw_seat, forfeit, vault_of_seat, VAULT_MAX, VAULT_MIN};
use std::collections::BTreeMap;

/// Every custodian's bond in the model (the pins' figure). A vault's bound is what its cheapest signing set forfeits
/// (`custody_vaults::forfeit`), at a repayment price of one.
pub const BOND: u128 = 5_000;

/// The whole custody state the lifecycle rules read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct World {
    /// seat → custodian
    pub seats: BTreeMap<u64, u32>,
    /// vault → what its ledgers stand behind
    pub held: BTreeMap<usize, u128>,
    /// vaults whose ledgers stand MOVED (`PegLedger::vault_ledgers_moved`): off their genesis pairs. A deposit moves
    /// them; only a merge returns them (a ledger's value is hidden, so "everything was cashed out" frees nothing —
    /// the rules below read THIS, as the node does, never `held`).
    pub moved: std::collections::BTreeSet<usize>,
    pub next_id: u32,
    pub deposited: u128,
    pub withdrawn: u128,
    /// What foreign fees took out of custody, with the same value retired from the supply by whoever paid (stage
    /// three's sweeps): conservation counts it.
    pub retired: u128,
    /// The moves the last rebalance made, `(from, into, amount)`: the coins follow them (stage three).
    pub last_moves: Vec<(usize, usize, u128)>,
    /// THE PARTS AT REST (`PegLedger::vault_parts`, spec §3g.1): giving vault → (the vault it is for, the part). A carve
    /// takes the part out of the giver's ledger; a take adds it to the receiver's, a cancel back to the giver's.
    pub parts: BTreeMap<usize, (usize, u128)>,
    /// The rotation day the receiver rule reads (`Node::rebalance_receiver_for`: finalized height over a rotation day).
    pub day: u64,
    /// set when a custodian was taken out against its will (a slash, seven days away): I6 speaks of leaving alone
    pub forced_exits: u64,
    /// CALIBRATION ONLY — the leave rule as first written (held only while another vault can take the ledgers), without
    /// "the last custodian of a funded vault does not leave". The model must be able to go red: under this rule it does.
    pub first_leave_rule: bool,
    /// CALIBRATION ONLY — the merge target as first written: the fullest other vault, whether or not it outranks the
    /// retiring one. Under it two thin vaults merge into each other for ever.
    pub any_other_vault_takes: bool,
    /// CALIBRATION ONLY — the part as first built: the smallest of an eighth, a quarter and a half that brings the giver
    /// inside its bound (a half when none does). Under it a vault far past its bound asks only for halves.
    pub first_part_rule: bool,
}

/// What an event did, for the invariants that speak about one event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Did {
    Bonded { seat: u64, split: bool },
    Left,
    Refused(&'static str),
    Deposited { vault: usize, alone: bool },
    Withdrew,
    Merged { from: usize, into: usize },
    Rebalanced(u32),
    Carved { from: usize, into: usize, part: u128 },
    Taken { from: usize, into: usize, part: u128 },
    Cancelled { from: usize, part: u128 },
    Nothing,
}

impl World {
    /// `n` custodians bonded one after the other under fixed randomness.
    #[must_use]
    pub fn with(n: u32) -> Self {
        let mut w = World::default();
        for i in 0..n {
            w.bond(&entropy(0xb0, u64::from(i)));
        }
        w
    }

    #[must_use]
    pub fn members(&self, vault: usize) -> usize {
        self.seats.keys().filter(|s| vault_of_seat(**s) == vault).count()
    }
    #[must_use]
    pub fn held(&self, vault: usize) -> u128 {
        self.held.get(&vault).copied().unwrap_or(0)
    }
    /// Every vault index that has a member, stands behind anything, or stands moved.
    #[must_use]
    pub fn vaults(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.seats.keys().map(|s| vault_of_seat(*s)).chain(self.held.iter().filter(|(_, h)| **h > 0).map(|(v, _)| *v)).chain(self.moved.iter().copied()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
    /// What vault `vault` may stand behind on its own quorum's word (`PegLedger::vault_authority_usdm`).
    #[must_use]
    pub fn bound(&self, vault: usize) -> u128 {
        forfeit(&vec![BOND; self.members(vault)])
    }
    /// The vault that takes `from`'s ledgers (`ValidatorSet::custody_merge_target`): the other vault with the most
    /// members, the lowest index among equals — and only when it OUTRANKS `from` (more members, or as many and a lower
    /// index). Ledgers move toward the strongest vault and stop there. FOUND 2026-11-11 by this model before the merge
    /// lane was built: with "any other vault with a member", two thin vaults hand the same ledgers back and forth
    /// (A merges into B, B is then thin with moved ledgers and merges into A), a foreign fee each time, and a custodian
    /// of the stronger one could never leave.
    #[must_use]
    pub fn merge_target(&self, from: usize) -> Option<usize> {
        let best = self.vaults().into_iter().filter(|v| *v != from && self.members(*v) > 0).max_by(|a, b| self.members(*a).cmp(&self.members(*b)).then(b.cmp(a)))?;
        if self.any_other_vault_takes {
            return Some(best);
        }
        ((self.members(best), std::cmp::Reverse(best)) > (self.members(from), std::cmp::Reverse(from))).then_some(best)
    }
    /// The vault a deposit goes to (`Node::deposit_vault_for`): spread by its nonce over the vaults of MORE than eight
    /// members; with none, the fullest vault (the lowest index among equals).
    #[must_use]
    pub fn route(&self, nonce: u64) -> Option<usize> {
        let vaults = self.vaults();
        let full: Vec<usize> = vaults.iter().copied().filter(|v| self.members(*v) > VAULT_MIN).collect();
        if !full.is_empty() {
            return Some(full[(nonce % full.len() as u64) as usize]);
        }
        vaults.into_iter().filter(|v| self.members(*v) > 0).max_by(|a, b| self.members(*a).cmp(&self.members(*b)).then(b.cmp(a)))
    }

    /// A BOND (`ValidatorSet::admit_active_from_drawn`): the seat is the draw's.
    pub fn bond(&mut self, entropy: &[u8; 32]) -> Did {
        let taken = self.seats.keys().copied().collect();
        let s = draw_seat(&taken, entropy);
        for (old, new) in &s.moved {
            let who = self.seats.remove(old).expect("a moved seat is held");
            assert!(self.seats.insert(*new, who).is_none(), "a split moved a member onto a held seat");
        }
        assert!(self.seats.insert(s.seat, self.next_id).is_none(), "the draw gave a held seat");
        self.next_id += 1;
        Did::Bonded { seat: s.seat, split: !s.moved.is_empty() }
    }

    /// A custodian LEAVES of its own accord (`Node::release_matured_bond` and its rule, `Node::custody_exit_held`).
    /// Refused while its vault's ledgers stand moved and the leave would take it under eight with another vault able to
    /// take its ledgers — or would leave nobody at all.
    pub fn leave(&mut self, seat: u64) -> Did {
        if !self.seats.contains_key(&seat) {
            return Did::Nothing;
        }
        let v = vault_of_seat(seat);
        if self.moved.contains(&v) {
            let m = self.members(v);
            if self.merge_target(v).is_some() && m <= VAULT_MIN {
                return Did::Refused("its vault is at half strength with its ledgers moved: the vault merges first");
            }
            if m <= 1 && !self.first_leave_rule {
                return Did::Refused("it is the last custodian of a vault that stands behind something");
            }
        }
        self.seats.remove(&seat);
        Did::Left
    }

    /// A custodian is TAKEN OUT (a slash, seven days away): no rule holds it.
    pub fn gone(&mut self, seat: u64) -> Did {
        if self.seats.remove(&seat).is_some() {
            self.forced_exits += 1;
            Did::Left
        } else {
            Did::Nothing
        }
    }

    /// A DEPOSIT (`PegLedger::vault_signed`): never refused. Its vault signs alone only at eight members and inside its
    /// bound; otherwise the whole set signs with it.
    pub fn deposit(&mut self, amount: u128, nonce: u64) -> Did {
        let Some(v) = self.route(nonce) else { return Did::Nothing }; // no custodian at all: no bridge
        let after = self.held(v) + amount;
        // a vault with a part out carries nothing on its own word (`vault_ride_holds`)
        let alone = self.members(v) >= VAULT_MIN && after <= self.bound(v) && !self.parts.contains_key(&v);
        self.held.insert(v, after);
        self.moved.insert(v);
        self.deposited += amount;
        Did::Deposited { vault: v, alone }
    }

    /// A CASH-OUT paid by `vault` (`PegLedger::burn_signed`): only from what that vault stands behind.
    pub fn withdraw(&mut self, vault: usize, amount: u128) -> Did {
        if amount == 0 || self.held(vault) < amount || self.members(vault) == 0 {
            return Did::Nothing;
        }
        *self.held.get_mut(&vault).expect("held") -= amount;
        self.withdrawn += amount;
        Did::Withdrew
    }

    /// A MERGE (`PegLedger::check_vault_merge`): out of a vault of eight or fewer whose ledgers stand moved, into the
    /// vault the rule names. The retiring vault's ledgers return to their genesis pairs.
    pub fn merge(&mut self, from: usize) -> Did {
        let m = self.members(from);
        if m == 0 || m > VAULT_MIN || !self.moved.contains(&from) {
            return Did::Refused("only a vault of eight or fewer whose ledgers stand moved merges");
        }
        if self.parts.iter().any(|(g, (r, _))| *g == from || *r == from) {
            return Did::Refused("a part at rest names the retiring vault: the slot closes first");
        }
        let Some(into) = self.merge_target(from) else { return Did::Refused("no other vault has a member") };
        let amount = self.held.remove(&from).unwrap_or(0);
        *self.held.entry(into).or_default() += amount;
        self.moved.remove(&from);
        self.moved.insert(into);
        Did::Merged { from, into }
    }

    /// THE PART A VAULT OWES (`PegLedger::rebalance_part_due`): an eighth of what it stands behind, floored, while it stands
    /// past its bound — whatever the excess, so any vault with room for an eighth can take it, and a vault far past its
    /// bound lands inside it over rounds (each leaves it seven eighths of what it held).
    #[must_use]
    pub fn part_due(&self, v: usize) -> Option<u128> {
        let (held, bound) = (self.held(v), self.bound(v));
        if held <= bound || !self.moved.contains(&v) {
            return None;
        }
        let shift = if self.first_part_rule { [3u32, 2, 1].into_iter().find(|k| held - (held >> k) <= bound).unwrap_or(1) } else { 3 };
        Some(held >> shift).filter(|p| *p > 0)
    }

    /// THE VAULT A CARVE OUT OF `from` IS FOR (`Node::rebalance_receiver_for`): the other vaults in index order, rotated by
    /// one each rotation day, the first of at least eight members with no part in or out.
    #[must_use]
    pub fn receiver_for(&self, from: usize) -> Option<usize> {
        let others: Vec<usize> = self.vaults().into_iter().filter(|v| *v != from && self.members(*v) > 0).collect();
        let n = others.len();
        (0..n).map(|k| others[(self.day as usize + k) % n]).find(|v| self.members(*v) >= VAULT_MIN && !self.parts.contains_key(v) && !self.parts.values().any(|(r, _)| r == v))
    }

    /// A CARVE (`PegLedger::vault_carve`): the part the vault owes leaves its ledger for the receiver the rule names.
    pub fn carve(&mut self, v: usize) -> Did {
        if self.parts.contains_key(&v) {
            return Did::Refused("one part at rest per vault");
        }
        let (Some(part), Some(into)) = (self.part_due(v), self.receiver_for(v)) else { return Did::Nothing };
        if self.parts.values().any(|(r, _)| *r == into) {
            return Did::Refused("one part at rest for a vault");
        }
        *self.held.get_mut(&v).expect("a vault past its bound holds") -= part;
        self.parts.insert(v, (into, part));
        Did::Carved { from: v, into, part }
    }

    /// A TAKE (`PegLedger::vault_take`): the receiver adds the part — only under its own bound proof after (the whole-set path
    /// is not built), so only with room and at least eight members.
    pub fn take(&mut self, v: usize) -> Did {
        let Some((into, part)) = self.parts.get(&v).copied() else { return Did::Nothing };
        if self.members(into) < VAULT_MIN || self.held(into) + part > self.bound(into) {
            return Did::Refused("the receiver has no room for the part on its own word");
        }
        self.parts.remove(&v);
        *self.held.entry(into).or_default() += part;
        self.moved.insert(into);
        Did::Taken { from: v, into, part }
    }

    /// A CANCEL (`PegLedger::vault_cancel`): the giver takes its part back (a rotation day after the carve, in the node).
    pub fn cancel(&mut self, v: usize) -> Did {
        let Some((_, part)) = self.parts.remove(&v) else { return Did::Nothing };
        *self.held.entry(v).or_default() += part;
        Did::Cancelled { from: v, part }
    }

    /// ONE REBALANCE ROUND (a rotation day of the lane, spec §3g.1): every vault that owes a part carves it; then each part
    /// is taken where its receiver has room, and otherwise taken back; the day turns, so the next round names the next
    /// receiver. The moves taken are `last_moves` (the coins follow them, `keys.rs`).
    pub fn rebalance(&mut self) -> Did {
        self.last_moves.clear();
        for v in self.vaults() {
            let _ = self.carve(v);
        }
        let mut moves = 0u32;
        for v in self.parts.keys().copied().collect::<Vec<_>>() {
            match self.take(v) {
                Did::Taken { from, into, part } => {
                    self.last_moves.push((from, into, part));
                    moves += 1;
                }
                _ => {
                    let _ = self.cancel(v);
                }
            }
        }
        self.day += 1;
        Did::Rebalanced(moves)
    }

    /// I1 and I3: true after every event.
    pub fn check(&self) {
        let mut ids: Vec<u32> = self.seats.values().copied().collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), self.seats.len(), "I1: a custodian sits on two seats");
        for v in self.vaults() {
            assert!(self.members(v) <= VAULT_MAX, "I1: vault {v} holds {} members", self.members(v));
        }
        // I3, with the parts at rest: a carve moves a part out of one ledger and into the slot, a take or a cancel out of the
        // slot into a ledger — never made, never lost
        let total: u128 = self.held.values().sum::<u128>() + self.parts.values().map(|(_, p)| *p).sum::<u128>();
        let want = self.deposited - self.withdrawn - self.retired;
        assert_eq!(total, want, "I3: the vaults and their parts at rest stand behind {total}; deposits less cash-outs less retired fees are {want}");
        // I10: one part out of and one part into a vault at a time
        for v in self.vaults() {
            assert!(self.parts.values().filter(|(r, _)| *r == v).count() <= 1, "I10: two parts at rest are for vault {v}");
        }
        for (v, h) in &self.held {
            assert!(*h == 0 || self.moved.contains(v), "a vault stands behind {h} on ledgers that never moved");
        }
    }
}

pub mod keys;

/// Chain randomness for the model: any 32 bytes.
#[must_use]
pub fn entropy(a: u64, b: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("custody-lifecycle-model");
    h.update(&a.to_le_bytes());
    h.update(&b.to_le_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One event of the alphabet the exhaustive search and the walks draw from.
    #[derive(Clone, Copy, Debug)]
    enum Ev {
        Bond,
        /// the lowest seat of the k-th vault leaves of its own accord
        Leave(usize),
        /// the lowest seat of the k-th vault is taken out
        Gone(usize),
        Deposit(u128, u64),
        Withdraw(usize, u128),
        Merge(usize),
        Rebalance,
        /// the k-th vault carves the part it owes; the part of the k-th vault's slot is taken; or taken back
        Carve(usize),
        Take(usize),
        Cancel(usize),
    }

    /// ⭐ I8 — THE BOUND IS TRANSIENT, as the built rule can deliver it: from `w`, rounds of the lane with nothing else
    /// happening leave a vault past its bound only while no vault of eight with no part in or out has room for an eighth
    /// of it — within `ROUNDS` rounds (each round takes an eighth; seven eighths a round from far past the bound is
    /// ln 2 / ln (8/7) ≈ 5.2 rounds a doubling, and every receiver is tried once in as many rounds as there are vaults).
    fn transient(w: &World) {
        const ROUNDS: u32 = 96;
        let mut r = w.clone();
        for _ in 0..ROUNDS {
            let _ = r.rebalance();
            r.check();
        }
        for v in r.vaults() {
            if r.held(v) > r.bound(v) {
                let eighth = r.held(v) >> 3;
                let room = r.vaults().into_iter().any(|u| u != v && r.members(u) >= VAULT_MIN && r.held(u) + eighth <= r.bound(u));
                assert!(!room || eighth == 0, "I8: after {ROUNDS} rounds vault {v} stands at {} past its bound {} while a vault of eight has room for an eighth", r.held(v), r.bound(v));
            }
        }
        assert!(r.parts.is_empty(), "a round closes every part it opened (taken or taken back)");
    }

    fn kth_vault(w: &World, k: usize) -> Option<usize> {
        let v = w.vaults();
        (!v.is_empty()).then(|| v[k % v.len()])
    }
    fn lowest_seat(w: &World, vault: usize) -> Option<u64> {
        w.seats.keys().copied().find(|s| vault_of_seat(*s) == vault)
    }

    /// Apply one event and check everything that must hold across it. `only_leaves`: no custodian was ever taken out,
    /// so I6 is asserted.
    fn step(w: &mut World, ev: Ev, n: u64) -> Did {
        let before = w.clone();
        let did = match ev {
            Ev::Bond => w.bond(&entropy(0xe0, n)),
            Ev::Leave(k) => kth_vault(w, k).and_then(|v| lowest_seat(w, v)).map_or(Did::Nothing, |s| w.leave(s)),
            Ev::Gone(k) => kth_vault(w, k).and_then(|v| lowest_seat(w, v)).map_or(Did::Nothing, |s| w.gone(s)),
            Ev::Deposit(a, nonce) => w.deposit(a, nonce),
            Ev::Withdraw(k, a) => kth_vault(w, k).map_or(Did::Nothing, |v| w.withdraw(v, a)),
            Ev::Merge(k) => kth_vault(w, k).map_or(Did::Nothing, |v| w.merge(v)),
            Ev::Rebalance => w.rebalance(),
            Ev::Carve(k) => kth_vault(w, k).map_or(Did::Nothing, |v| w.carve(v)),
            Ev::Take(k) => kth_vault(w, k).map_or(Did::Nothing, |v| w.take(v)),
            Ev::Cancel(k) => kth_vault(w, k).map_or(Did::Nothing, |v| w.cancel(v)),
        };
        w.check();
        let changed = |a: &World, b: &World| -> usize { a.vaults().into_iter().chain(b.vaults()).collect::<std::collections::BTreeSet<_>>().into_iter().filter(|v| a.members(*v) != b.members(*v)).count() };
        match &did {
            Did::Bonded { seat, split } => {
                assert_eq!(changed(&before, w), if *split { 2 } else { 1 }, "I2: a bond changed {} vault(s)", changed(&before, w));
                let joined = before.members(vault_of_seat(*seat));
                let eight_exists = before.vaults().iter().any(|v| before.members(*v) >= VAULT_MIN);
                assert!(*split || !eight_exists || joined >= VAULT_MIN, "I2: a newcomer joined a vault of {joined} while a vault of eight exists");
            }
            Did::Deposited { vault, alone } => {
                if *alone {
                    assert!(w.members(*vault) >= VAULT_MIN && w.held(*vault) <= w.bound(*vault), "I4: a vault signed alone under eight members or past its bound");
                    assert!(!w.parts.contains_key(vault), "I4: a vault with a part out signed a deposit on its own word");
                }
                let roomy = before.vaults().into_iter().any(|v| before.members(v) > VAULT_MIN);
                assert!(!roomy || before.members(*vault) > VAULT_MIN, "I5: a deposit went to a vault of {} while a vault of more than eight exists", before.members(*vault));
            }
            Did::Merged { from, into } => {
                assert!(before.members(*from) <= VAULT_MIN && before.members(*from) > 0 && before.moved.contains(from), "I7: a merge out of a vault that may not merge");
                assert!(!w.moved.contains(from), "I7: the retiring vault's ledgers did not return to their genesis pairs");
                assert_eq!((w.held(*from), w.held(*into)), (0, before.held(*into) + before.held(*from)), "I7: the merge did not move the whole holding");
            }
            Did::Rebalanced(_) => assert!(w.parts.is_empty(), "a round closes every part it opened"),
            Did::Carved { from, into, part } => {
                assert!(before.held(*from) > before.bound(*from) && *part == before.held(*from) >> 3, "a carve out of a vault inside its bound, or of another part than an eighth");
                assert!(*into != *from && before.members(*into) >= VAULT_MIN, "a part carved for itself or for a vault under eight");
            }
            Did::Taken { into, part, .. } => assert!(w.held(*into) <= w.bound(*into) && before.held(*into) + part == w.held(*into), "a take past the receiver's bound"),
            Did::Cancelled { from, part } => assert_eq!(w.held(*from), before.held(*from) + part, "a cancel added back another part"),
            Did::Left | Did::Refused(_) | Did::Withdrew | Did::Nothing => {}
        }
        if matches!(ev, Ev::Deposit(..)) && before.route(0).is_some() {
            assert!(matches!(did, Did::Deposited { .. }), "I5: a deposit was refused");
        }
        // I6, for a world nobody was ever taken out of
        if w.forced_exits == 0 {
            for v in w.vaults() {
                if w.moved.contains(&v) {
                    assert!(w.members(v) >= 1, "I6: vault {v}'s ledgers stand moved (behind {}) with NO custodian, and nobody was taken out", w.held(v));
                }
            }
            if let (Ev::Leave(_), Did::Left) = (ev, &did) {
                for v in w.vaults() {
                    // the vault the leaver left: if it stands behind something and could have merged, it kept eight
                    if before.members(v) == w.members(v) + 1 && w.moved.contains(&v) && before.merge_target(v).is_some() {
                        assert!(w.members(v) >= VAULT_MIN, "I6: a custodian walked out of vault {v}, leaving {} with its ledgers moved and a vault able to take them", w.members(v));
                    }
                }
            }
        }
        did
    }

    const ALPHABET: [Ev; 16] = [
        Ev::Bond,
        Ev::Leave(0),
        Ev::Leave(1),
        Ev::Leave(2),
        Ev::Gone(0),
        Ev::Gone(1),
        Ev::Deposit(1_000, 0),
        Ev::Deposit(40_000, 1),
        Ev::Withdraw(0, 500),
        Ev::Withdraw(1, 500),
        Ev::Merge(0),
        Ev::Merge(1),
        Ev::Rebalance,
        Ev::Carve(0),
        Ev::Take(0),
        Ev::Cancel(1),
    ];

    /// ⭐ EVERY SEQUENCE of five events from six starting sets (1, 8, 16, 17, 33 and 49 custodians): 16^5 = 1,048,576
    /// sequences each, every invariant checked after every event, and the bound's transience (I8) from every 64th end
    /// state (it runs the lane's rounds forward).
    #[test]
    fn every_sequence_of_five_events_keeps_every_invariant() {
        let mut sequences = 0u64;
        for start in [1u32, 8, 16, 17, 33, 49] {
            let base = World::with(start);
            base.check();
            let mut idx = [0usize; 5];
            loop {
                let mut w = base.clone();
                for (n, i) in idx.iter().enumerate() {
                    step(&mut w, ALPHABET[*i], n as u64);
                }
                if sequences % 64 == 0 {
                    transient(&w);
                }
                sequences += 1;
                let mut k = 0;
                while k < idx.len() {
                    idx[k] += 1;
                    if idx[k] < ALPHABET.len() {
                        break;
                    }
                    idx[k] = 0;
                    k += 1;
                }
                if k == idx.len() {
                    break;
                }
            }
        }
        eprintln!("[model] {sequences} sequences of five events, every invariant held after every event");
        assert_eq!(sequences, 6 * 16u64.pow(5));
    }

    /// ⛔ THE RULE THIS MODEL FOUND WRONG (2026-11-12, before any of it ran): the part as first built was "the smallest of an
    /// eighth, a quarter and a half that brings the giver inside its bound" — so a vault at twice its bound always asked for
    /// HALF, and when no single vault had room for half it stood past its bound for ever, though several vaults could each
    /// take an eighth. CALIBRATION: one vault of 16 at twice its bound and four vaults of 16, each with room for two fifths of a
    /// bound (1.6 bounds in all, against an excess of one) — under the first rule no round moves anything (no vault has room
    /// for a half); under the rule as built (an eighth a round) the vault lands inside.
    #[test]
    fn a_vault_far_past_its_bound_lands_inside_it_by_eighths_where_no_vault_could_take_a_half() {
        let mut w = World::with(80); // five vaults of sixteen: the four others hold room for 1.6 bounds, the excess is one
        let vs = w.vaults();
        assert_eq!(vs.iter().map(|v| w.members(*v)).collect::<Vec<_>>(), vec![16; 5], "PRECONDITION: five full vaults");
        let (big, others) = (vs[0], &vs[1..]);
        // the big vault twice past its bound; the others each a fifth of it short of theirs
        let bound = w.bound(big);
        w.held.insert(big, 2 * bound);
        w.moved.insert(big);
        for u in others {
            w.held.insert(*u, bound - (2 * bound) / 5);
            w.moved.insert(*u);
        }
        w.deposited = w.held.values().sum();
        w.check();
        // the first rule's part: a half (no listed fraction brings 2·bound inside bound) — no vault has room for it
        let half = w.held(big) / 2;
        assert!(others.iter().all(|u| w.held(*u) + half > w.bound(*u)), "CALIBRATION: no vault has room for a half");
        let rounds = |first_part_rule: bool| -> World {
            let mut r = w.clone();
            r.first_part_rule = first_part_rule;
            for _ in 0..40 {
                let _ = r.rebalance();
                r.check();
            }
            r
        };
        let first = rounds(true);
        assert_eq!(first.held(big), 2 * bound, "CALIBRATION: under the first part rule forty rounds move nothing — the model can go red");
        let built = rounds(false);
        assert!(built.held(big) <= built.bound(big), "⛔ a vault twice past its bound is still past it ({} of {}) after 40 rounds of eighths", built.held(big), built.bound(big));
        eprintln!("[model] a vault at twice its bound: the first part rule moved nothing in 40 rounds; eighths brought it to {} of {bound}", built.held(big));
        transient(&w);
    }

    /// Long random walks: 200 walks of 2,000 events, half of them with nobody ever taken out (so I6 is asserted for the
    /// whole walk), with every seat a candidate to leave.
    #[test]
    fn long_random_walks_keep_every_invariant() {
        let mut events = 0u64;
        for walk in 0..200u64 {
            let forced = walk % 2 == 1;
            let mut w = World::with(1 + (walk as u32 * 7) % 60);
            for n in 0..2_000u64 {
                let e = entropy(walk, n);
                let pick = u64::from_le_bytes(e[..8].try_into().unwrap());
                let any_seat = |w: &World| -> Option<u64> { let all: Vec<u64> = w.seats.keys().copied().collect(); (!all.is_empty()).then(|| all[(pick >> 8) as usize % all.len()]) };
                let ev = match pick % 16 {
                    0..=4 => Ev::Bond,
                    5..=7 => {
                        if let Some(s) = any_seat(&w) {
                            let before = w.clone();
                            let did = w.leave(s);
                            w.check();
                            if w.forced_exits == 0 && did == Did::Left {
                                let v = vault_of_seat(s);
                                assert!(!w.moved.contains(&v) || w.members(v) >= 1, "I6: the last custodian walked away from a ledger");
                                assert!(!w.moved.contains(&v) || before.merge_target(v).is_none() || w.members(v) >= VAULT_MIN, "I6: a leave thinned a vault with moved ledgers under eight");
                            }
                        }
                        events += 1;
                        continue;
                    }
                    8 if forced => Ev::Gone((pick >> 16) as usize),
                    8 | 9 | 10 => Ev::Deposit(u128::from(1 + (pick >> 20) % 30_000), pick >> 40),
                    11 | 12 => Ev::Withdraw((pick >> 16) as usize, u128::from(1 + (pick >> 20) % 5_000)),
                    13 => Ev::Merge((pick >> 16) as usize),
                    _ => Ev::Rebalance,
                };
                step(&mut w, ev, n);
                events += 1;
            }
        }
        eprintln!("[model] {events} events over 200 walks, every invariant held");
    }

    /// I9 — a custodian that wants out of a thin vault can get out: the vault merges, then the leave is taken.
    #[test]
    fn a_custodian_of_a_thin_vault_leaves_after_the_merge() {
        let mut w = World::with(33); // a split has happened: more than one vault
        w.check();
        let deposits: Vec<(usize, u128)> = (0..8u64).filter_map(|n| if let Did::Deposited { vault, .. } = w.deposit(1_000, n) { Some((vault, 1_000)) } else { None }).collect();
        let thin = deposits[0].0;
        // take members out until the vault is at eight: a slash is never held back
        while w.members(thin) > VAULT_MIN {
            let s = w.seats.keys().copied().find(|s| vault_of_seat(*s) == thin).unwrap();
            w.gone(s);
        }
        let s = w.seats.keys().copied().find(|s| vault_of_seat(*s) == thin).unwrap();
        assert!(matches!(w.leave(s), Did::Refused(_)), "CALIBRATION: at eight, with its ledgers moved and a vault to take them, the leave is refused");
        assert!(matches!(w.merge(thin), Did::Merged { .. }), "the vault merges");
        assert!(w.held(thin) == 0 && !w.moved.contains(&thin), "its ledgers are back on their genesis pairs");
        assert_eq!(w.leave(s), Did::Left, "I9: after the merge the custodian leaves");
        w.check();
    }

    /// ⛔ THE RULE THE MODEL FOUND MISSING (2026-11-11): with "a leave is held only while another vault can take the
    /// ledgers" and nothing else, the custodians of the only vault can all leave and its ledger stands behind
    /// deposits with nobody. CALIBRATION: this walk, under that rule alone, ends with a funded vault and no custodian;
    /// under the rule as built (the last custodian of a funded vault does not leave) one stays.
    #[test]
    fn the_last_custodian_of_a_funded_vault_does_not_leave() {
        // CALIBRATION — the model can go red: under the rule as first written, the search itself reaches a funded vault
        // with no custodian within five events, and the invariant check panics on it.
        let found = std::panic::catch_unwind(|| {
            let mut base = World::with(2);
            base.first_leave_rule = true;
            for a in ALPHABET {
                for b in ALPHABET {
                    for c in ALPHABET {
                        let mut w = base.clone();
                        for (n, ev) in [a, b, c].into_iter().enumerate() {
                            step(&mut w, ev, n as u64);
                        }
                    }
                }
            }
        });
        assert!(found.is_err(), "CALIBRATION: under the first leave rule the search must find the stranded ledger (deposit, leave, leave)");
        let mut w = World::with(3);
        assert!(matches!(w.deposit(1_000, 0), Did::Deposited { .. }));
        let seats: Vec<u64> = w.seats.keys().copied().collect();
        assert_eq!(w.leave(seats[0]), Did::Left, "a one-vault chain has no vault to merge into: a custodian leaves, as before vaults");
        assert_eq!(w.leave(seats[1]), Did::Left);
        assert!(matches!(w.leave(seats[2]), Did::Refused(_)), "⛔ the last custodian walked away from a ledger that stands behind deposits");
        assert_eq!((w.members(0), w.held(0)), (1, 1_000));
        // The chain cannot see that a ledger holds nothing (its value is hidden): cashing everything out frees nobody.
        assert!(matches!(w.withdraw(0, 1_000), Did::Withdrew));
        assert!(matches!(w.leave(seats[2]), Did::Refused(_)), "the node's rule reads MOVED, not empty: the last custodian still stays (the stated cost of the rule)");
        // What frees it: another custodian bonds, so the ledger keeps a custodian.
        assert!(matches!(w.bond(&entropy(0xf0, 0)), Did::Bonded { .. }));
        assert_eq!(w.leave(seats[2]), Did::Left, "with another custodian seated it leaves");
        assert_eq!(w.members(0), 1);
    }

    /// ⛔ THE SECOND RULE THE MODEL FOUND (2026-11-11): "the fullest other vault takes a thin vault's ledgers" lets two
    /// thin vaults hand the same ledgers back and forth for ever — each hand-over a foreign sweep fee, and a custodian
    /// of the stronger one never free to leave. CALIBRATION: under that rule every pass over the vaults finds another
    /// merge due; under the rule as built (the target must OUTRANK the retiring vault) the ledgers move once, to the
    /// stronger vault, and stay.
    #[test]
    fn two_thin_vaults_do_not_hand_their_ledgers_back_and_forth() {
        let merges_in_ten_passes = |any_other_vault_takes: bool| -> u32 {
            let mut w = World::with(17); // the seventeenth bond split the full vault: two vaults
            w.any_other_vault_takes = any_other_vault_takes;
            let Did::Deposited { vault: funded, .. } = w.deposit(1_000, 0) else { panic!("a deposit is never refused") };
            let other = w.vaults().into_iter().find(|v| *v != funded).expect("two vaults");
            // slashes thin both: the funded vault to five, the other to six (a slash is never held back)
            for (v, keep) in [(funded, 5usize), (other, 6)] {
                while w.members(v) > keep {
                    let s = w.seats.keys().copied().find(|s| vault_of_seat(*s) == v).unwrap();
                    w.gone(s);
                }
            }
            let mut merges = 0;
            for _ in 0..10 {
                for v in w.vaults() {
                    if w.members(v) <= VAULT_MIN && w.moved.contains(&v) && matches!(w.merge(v), Did::Merged { .. }) {
                        merges += 1;
                    }
                }
                w.check();
            }
            assert!(w.moved.len() == 1 && w.held.values().sum::<u128>() == 1_000, "the ledgers are in one vault, whole");
            if !any_other_vault_takes {
                assert!(w.moved.contains(&other), "…the stronger one");
            }
            merges
        };
        assert!(merges_in_ten_passes(true) >= 10, "CALIBRATION: under the first target rule the two vaults keep merging into each other");
        assert_eq!(merges_in_ten_passes(false), 1, "⛔ a thin vault's ledgers moved more than once: they go to the vault that outranks it and stay");
    }
}

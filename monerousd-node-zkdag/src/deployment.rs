// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BR-10 U1–U4 (DB-392, owner decisions 2026-10-05) — SIGNALLED DEPLOYMENTS: how every rule change after launch ships.
//!
//! The Bitcoin model: every node chooses the release it runs; there is no installer and no update key. A rule change is a
//! DEPLOYMENT in the compiled table [`DEPLOYMENTS`] (empty at genesis: everything that ships at launch is active at height 1).
//! Borrowed shapes, cited: BIP9 version bits in `header.version` (top bits `001`, bits 0–28 signal); Kaspa's blue-score
//! clock for the windows; BIP90 burial once active. MonerousD's own rule (owner decision): BICAMERAL activation — a window
//! LOCKS IN only when ≥ 90 % of its folded blue blocks signal (miners) AND ≥ 2/3 of custody bond signalled (validators, by a
//! vote-key-signed [`crate::deployment_signal_tx`] object). One window = one reward epoch (`params.reward_epoch_blocks`).
//!
//! State is a function of the chain: the canonical fold counts every folded block in canonical order (`Node::deployment_
//! fold_step`), the ledger lives in the peg ledger (journaled with the fold step, persisted, certified), so every node reaches
//! the same state from the same chain. The rule-set id ([`rule_set_id`]) names the active deployments; it rides `/get_info`
//! and the handshake, so two nodes on different rule sets know it at once (EIP-2124's fork id).
//! cons: one counter per deployment and one validator set per open window (bounded by the seat set); zero at genesis.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// BIP9: a version whose top three bits are `001` carries signal bits.
pub const VERSION_TOP_MASK: u32 = 0xE000_0000;
pub const VERSION_TOP_BITS: u32 = 0x2000_0000;
/// The highest usable signal bit.
pub const MAX_BIT: u8 = 28;
/// The miners' threshold: signalling blue blocks per 10 000 of a window's folded blue blocks.
pub const MINER_THRESHOLD_BPS: u64 = 9_000;

/// ⭐ §BR-10 THE EMERGENCY LANE (spec §8 item 2): an emergency deployment counts in its OWN short window — ONE HOUR OF CHAIN
/// TIME — instead of a reward epoch, with the same bicameral thresholds. Bitcoin Core's per-deployment BIP9 `period` (each
/// deployment names its own signalling window length), cited. Tighten-only is a property of the RELEASE, proven before it
/// ships by `scratchpad/emergency_replay_check.sh` (the chain cannot judge what a rule refuses).
/// ⭐ A-F60 (user 2026-11-15: "there should be no assumptions in our blockchain"): the hour is a TIME, so the lane's windows
/// are counted in CHAIN TICKS ([`FAST_WINDOW_TICKS`], `Node::chain_tick_at`), never in blocks at the target pace — an hour
/// of target blocks is several hours on a mesh slower than its target, and an emergency fix would wait that long. Its
/// thresholds stay fractions of the blocks the window actually folded, so the pace never moves a verdict; an emergency
/// deployment's `start` and `timeout` are chain ticks (BIP9's own clock for them is median time past).
/// The normal lane keeps BIP8's shape: windows of `reward_epoch_blocks` BLOCKS and heights for `start`/`timeout` — a count
/// of blocks is what it means there (a signalling sample), never a time.
pub const EMERGENCY_WINDOW_MS: u64 = 3_600_000;

/// The emergency window in chain ticks: one hour of chain time (A-F60).
pub const FAST_WINDOW_TICKS: u64 = crate::params::blocks_for_ms(EMERGENCY_WINDOW_MS);

/// A validator signal for the FAST (emergency) window carries this bit (bit 31 — above every signal bit, `MAX_BIT` = 28): the
/// class is named by the object itself, so its one-time id never depends on which deployments a release knows.
pub const FAST_SIGNAL: u32 = 1 << 31;

/// One deployment, as a release compiles it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub name: &'static str,
    pub bit: u8,
    /// The first blue score whose window may start signalling.
    pub start: u64,
    /// Past this blue score a deployment that never locked in fails.
    pub timeout: u64,
    /// ⭐ An EMERGENCY deployment (a tighten-only security fix): counted in the fast window ([`EMERGENCY_WINDOW_MS`]).
    pub emergency: bool,
}

/// The deployments this release knows — EMPTY at genesis (every launch rule is active at height 1). A release adds one here
/// with a start in the future; it never signals for anything outside its own table.
pub const DEPLOYMENTS: &[Deployment] = &[];

/// The table this release compiles.
#[must_use]
pub fn deployments() -> Vec<Deployment> {
    DEPLOYMENTS.to_vec()
}

/// A deployment's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DeployState {
    #[default]
    Defined,
    Started,
    LockedIn,
    /// Active from the start of this window index.
    Active(u64),
    Failed,
}

/// ⭐ THE LEDGER — the open window's counts and every deployment's state, keyed by deployment NAME (a release that drops a
/// buried deployment from its table keeps its state readable). Lives inside the peg ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentLedger {
    /// The open window's index (`blue_score / window`), and whether any block has been counted in it.
    pub window: u64,
    pub opened: bool,
    /// Folded blue blocks counted in the open window.
    pub blocks: u64,
    /// Per deployment: signalling blocks in the open window.
    pub signals: BTreeMap<String, u64>,
    /// Per deployment: the validators that signalled in the open window (bounded by the seat set).
    pub signalled_validators: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// Per deployment: its state.
    pub states: BTreeMap<String, DeployState>,
    /// Folded blocks in the open window signalling a bit this release does not know (Bitcoin Core's unknown-version-bits
    /// warning).
    #[serde(default)]
    pub unknown_blocks: u64,
    /// ⭐ Set once a whole window's blocks (≥ 90 %) signalled a bit this release does not know: a deployment this node cannot
    /// enforce may be locking in. The node keeps following the one DAG; the wallet says "Update needed to keep validating
    /// new rules" (spec §8). Never cleared by this release.
    #[serde(default)]
    pub update_needed: bool,
    /// ⭐ §BR-10 the emergency lane's own window: emergency deployments are counted here and nowhere else.
    #[serde(default)]
    pub fast: FastWindow,
    /// Test builds only: a stand-in fast-window length (blue blocks) on THIS ledger. Never serialized.
    #[cfg(test)]
    #[serde(skip)]
    pub test_fast_window: Option<u64>,
    /// Test builds only: a stand-in table on THIS ledger (so a pin's nodes see it and no concurrent test does). Never
    /// serialized.
    #[cfg(test)]
    #[serde(skip)]
    pub test_table: Option<Vec<Deployment>>,
}

/// ⭐ The emergency lane's open window: its index (`blue_score / fast window`), the folded blue blocks counted in it, and per
/// emergency deployment the signalling blocks and the validators that signalled (bounded by the seat set).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastWindow {
    pub window: u64,
    pub opened: bool,
    pub blocks: u64,
    pub signals: BTreeMap<String, u64>,
    pub signalled_validators: BTreeMap<String, BTreeSet<[u8; 32]>>,
}

/// Step every deployment of `table` at the close of window `window` (scores `[window·len, (window+1)·len)`) for the NEXT
/// window, whose first score is `next = (window+1)·len`: Defined → Started once `next ≥ start`; Started → LockedIn on both
/// thresholds, else → Failed once `next ≥ timeout`; LockedIn → Active from the next window (index `window + 1`). ONE rule for
/// both lanes (the normal window and the emergency window), so the two can never disagree on what a threshold means.
#[allow(clippy::too_many_arguments)]
fn step_states(
    states: &mut BTreeMap<String, DeployState>,
    table: &[Deployment],
    window: u64,
    window_len: u64,
    blocks: u64,
    signals: &BTreeMap<String, u64>,
    validators: &BTreeMap<String, BTreeSet<[u8; 32]>>,
    total_bond: u128,
    bond_of_signalled: &dyn Fn(&BTreeSet<[u8; 32]>) -> u128,
) {
    let next = window.saturating_add(1).saturating_mul(window_len.max(1));
    for d in table {
        let name = d.name.to_string();
        // a deployment never seen is Defined (BIP9's initial state)
        let now = match states.get(d.name) {
            Some(s) => *s,
            None => DeployState::Defined,
        };
        let state = match now {
            DeployState::Defined if next >= d.timeout => DeployState::Failed,
            DeployState::Defined if next >= d.start => DeployState::Started,
            DeployState::Started => {
                // no signalling block counted in the window is zero signalling blocks
                let sig = match signals.get(&name) {
                    Some(n) => *n,
                    None => 0,
                };
                let miners = blocks > 0 && u128::from(sig) * 10_000 >= u128::from(blocks) * u128::from(MINER_THRESHOLD_BPS);
                // no validator signalled in the window: no bond signalled
                let vbond = match validators.get(&name) {
                    Some(set) => bond_of_signalled(set),
                    None => 0,
                };
                let validators = total_bond > 0 && vbond.saturating_mul(3) >= total_bond.saturating_mul(2);
                if miners && validators {
                    DeployState::LockedIn
                } else if next >= d.timeout {
                    DeployState::Failed
                } else {
                    DeployState::Started
                }
            }
            DeployState::LockedIn => DeployState::Active(window.saturating_add(1)),
            s => s,
        };
        states.insert(name, state);
    }
}

impl DeploymentLedger {
    /// The table this ledger counts against: the release's ([`deployments`]), or a test build's stand-in.
    #[must_use]
    pub fn table(&self) -> Vec<Deployment> {
        #[cfg(test)]
        if let Some(t) = &self.test_table {
            return t.clone();
        }
        deployments()
    }
    /// Whether any deployment can move this ledger (the release has one, or a state is already recorded).
    #[must_use]
    pub fn live(&self) -> bool {
        !self.table().is_empty() || !self.states.is_empty() || self.opened || self.fast.opened
    }
    /// The fast window's length in chain ticks: [`FAST_WINDOW_TICKS`] as the caller passes it, or a test build's stand-in
    /// on this ledger.
    #[must_use]
    pub fn fast_len(&self, given: u64) -> u64 {
        #[cfg(test)]
        if let Some(w) = self.test_fast_window {
            return w.max(1);
        }
        given.max(1)
    }
    /// Whether a block of `version` moves this ledger: while any deployment is live, or whenever the block signals bits.
    #[must_use]
    pub fn moved_by(&self, version: u32) -> bool {
        self.live() || version & VERSION_TOP_MASK == VERSION_TOP_BITS
    }
    /// A deployment's state (Defined if never seen).
    #[must_use]
    pub fn state(&self, name: &str) -> DeployState {
        self.states.get(name).copied().unwrap_or_default()
    }
    /// Whether `name` is active.
    #[must_use]
    pub fn is_active(&self, name: &str) -> bool {
        matches!(self.state(name), DeployState::Active(_))
    }
    /// The header version a producer lays at blue score `score`: the BIP9 top bits plus the bit of every deployment in this
    /// release's table that is Started (or LockedIn) — a release signals only for what it implements. With nothing to signal
    /// the version stays 1, byte-identical to every block before deployments existed.
    #[must_use]
    pub fn version_for(&self, score: u64) -> u32 {
        let bits = self
            .table()
            .iter()
            .filter(|d| d.bit <= MAX_BIT && score >= d.start && score < d.timeout)
            .filter(|d| matches!(self.state(d.name), DeployState::Started | DeployState::LockedIn))
            .fold(0u32, |acc, d| acc | (1u32 << d.bit));
        if bits == 0 { 1 } else { VERSION_TOP_BITS | bits }
    }
    /// A fixture's door into [`Self::observe_block_at`] whose blocks sit one chain tick apart (tick = score). Tests only.
    #[cfg(test)]
    pub fn observe_block(
        &mut self,
        score: u64,
        version: u32,
        window_len: u64,
        fast_window_len: u64,
        total_bond: u128,
        bond_of_signalled: &dyn Fn(&BTreeSet<[u8; 32]>) -> u128,
    ) -> bool {
        self.observe_block_at(score, score, version, window_len, fast_window_len, total_bond, bond_of_signalled)
    }

    /// ⭐ COUNT one folded blue block (canonical order) at blue score `score` and chain tick `tick` with header `version`,
    /// closing an open window first when the block is past it: the normal lane by `score` (BIP8: windows of blocks), the
    /// emergency lane by `tick` (an hour of chain time, A-F60). `bond_of_signalled(name)` and `total_bond` are read at a
    /// close (the validator set the fold holds then). Returns whether anything moved.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_block_at(
        &mut self,
        score: u64,
        tick: u64,
        version: u32,
        window_len: u64,
        fast_window_len: u64,
        total_bond: u128,
        bond_of_signalled: &dyn Fn(&BTreeSet<[u8; 32]>) -> u128,
    ) -> bool {
        let all = self.table();
        let signalling = version & VERSION_TOP_MASK == VERSION_TOP_BITS;
        if all.is_empty() && self.states.is_empty() && !self.opened && !self.fast.opened && !signalling {
            return false; // nothing to deploy and nothing signalled: the ledger never moves (the launch state)
        }
        let known = all.iter().filter(|d| d.bit <= MAX_BIT).fold(0u32, |a, d| a | (1u32 << d.bit));
        let fast: Vec<Deployment> = all.iter().filter(|d| d.emergency).copied().collect();
        let table: Vec<Deployment> = all.iter().filter(|d| !d.emergency).copied().collect();
        // ⭐ the emergency lane: its own window, its own counts, the same rule
        if !fast.is_empty() || self.fast.opened {
            let fl = self.fast_len(fast_window_len);
            let fw = tick / fl;
            if !self.fast.opened {
                self.fast.window = fw;
                self.fast.opened = true;
            }
            while fw > self.fast.window {
                step_states(
                    &mut self.states,
                    &fast,
                    self.fast.window,
                    fl,
                    self.fast.blocks,
                    &self.fast.signals,
                    &self.fast.signalled_validators,
                    total_bond,
                    bond_of_signalled,
                );
                self.fast.blocks = 0;
                self.fast.signals.clear();
                self.fast.signalled_validators.clear();
                self.fast.window += 1;
            }
            self.fast.blocks += 1;
            for d in &fast {
                if signalling && d.bit <= MAX_BIT && version & (1u32 << d.bit) != 0 && self.state(d.name) == DeployState::Started {
                    *self.fast.signals.entry(d.name.to_string()).or_insert(0) += 1;
                }
            }
        }
        let w = score / window_len.max(1);
        if !self.opened {
            self.window = w;
            self.opened = true;
        }
        // a gap of several windows closes each one in turn (an empty window counts no block and never locks in)
        while w > self.window {
            self.close_window(&table, window_len, total_bond, bond_of_signalled);
            self.window += 1;
        }
        self.blocks += 1;
        if signalling && version & !VERSION_TOP_MASK & !known != 0 {
            self.unknown_blocks += 1;
        }
        for d in &table {
            if signalling && d.bit <= MAX_BIT && version & (1u32 << d.bit) != 0 && self.state(d.name) == DeployState::Started {
                *self.signals.entry(d.name.to_string()).or_insert(0) += 1;
            }
        }
        true
    }
    /// A validator's signal for the open window (the fold applies a verified `DeploymentSignal`): counted only for a
    /// deployment in this release's table that is Started, and only once per validator per window.
    /// A signal carrying [`FAST_SIGNAL`] is for the emergency window and counts only for emergency deployments; one without it
    /// is for the normal window and counts only for normal ones — neither lane's signal ever moves the other's counts.
    pub fn observe_validator_signal(&mut self, vid: [u8; 32], bits: u32, window: u64) -> bool {
        let fast = bits & FAST_SIGNAL != 0;
        let (opened, open_window) = if fast { (self.fast.opened, self.fast.window) } else { (self.opened, self.window) };
        if !opened || window != open_window {
            return false;
        }
        let named: Vec<String> = self
            .table()
            .iter()
            .filter(|d| d.emergency == fast && d.bit <= MAX_BIT && bits & (1u32 << d.bit) != 0)
            .filter(|d| self.state(d.name) == DeployState::Started)
            .map(|d| d.name.to_string())
            .collect();
        let sets = if fast { &mut self.fast.signalled_validators } else { &mut self.signalled_validators };
        let mut moved = false;
        for n in named {
            moved |= sets.entry(n).or_default().insert(vid);
        }
        moved
    }
    /// Close the open window (scores `[window·len, (window+1)·len)`) and step every deployment for the NEXT window, whose
    /// first score is `next = (window+1)·len`: Defined → Started once `next ≥ start`; Started → LockedIn on both
    /// thresholds, else → Failed once `next ≥ timeout`; LockedIn → Active from the next window (index `window + 1`).
    fn close_window(
        &mut self,
        table: &[Deployment],
        window_len: u64,
        total_bond: u128,
        bond_of_signalled: &dyn Fn(&BTreeSet<[u8; 32]>) -> u128,
    ) {
        if self.blocks > 0 && u128::from(self.unknown_blocks) * 10_000 >= u128::from(self.blocks) * u128::from(MINER_THRESHOLD_BPS) {
            self.update_needed = true;
        }
        self.unknown_blocks = 0;
        step_states(
            &mut self.states,
            table,
            self.window,
            window_len,
            self.blocks,
            &self.signals,
            &self.signalled_validators,
            total_bond,
            bond_of_signalled,
        );
        self.blocks = 0;
        self.signals.clear();
        self.signalled_validators.clear();
    }
}

/// ⭐ THE RULE-SET ID — `H(network ‖ every active deployment's name, sorted)`: the same on every node of one rule set, and it
/// changes the instant a deployment activates. Carried by `/get_info` and the handshake (EIP-2124's fork id).
#[must_use]
pub fn rule_set_id(network: &str, ledger: &DeploymentLedger) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/rule-set/v1");
    h.update(network.as_bytes());
    let mut active: Vec<&String> = ledger.states.iter().filter(|(_, s)| matches!(s, DeployState::Active(_))).map(|(n, _)| n).collect();
    active.sort();
    for n in active {
        h.update(&(n.len() as u32).to_le_bytes());
        h.update(n.as_bytes());
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> Deployment {
        Deployment { name: "test-rule", bit: 3, start: 100, timeout: 1_000, emergency: false }
    }

    /// ⭐ THE STATE MACHINE, BICAMERAL: a deployment starts in the first window at or past its start; a window where 90 % of
    /// blocks AND 2/3 of bond signalled locks it in; it is active one window later; the rule-set id changes then and only
    /// then. TAMPERS: 89 % of blocks with all the bond, all the blocks with half the bond, and a release with nothing to
    /// signal (the version stays 1) each never lock in; a deployment past its timeout fails.
    #[test]
    fn a_deployment_activates_only_on_90_percent_of_blocks_and_two_thirds_of_bond_one_window_after_lock_in() {
        let w = 100u64;
        let v = [1u8; 32];
        let run = |miner_pct: u64, bond_signalled: u128| -> DeploymentLedger {
            let mut l = DeploymentLedger { test_table: Some(vec![d()]), ..DeploymentLedger::default() };
            let bond = |set: &BTreeSet<[u8; 32]>| if set.contains(&v) { bond_signalled } else { 0 };
            for score in 0..400u64 {
                let signal = (score % 100) < miner_pct;
                let version = if signal { VERSION_TOP_BITS | (1 << 3) } else { 1 };
                l.observe_block(score, version, w, 10, 300, &bond);
                l.observe_validator_signal(v, 1 << 3, l.window);
            }
            l
        };
        let id0 = rule_set_id("testnet", &DeploymentLedger::default());
        let ok = run(90, 200);
        assert_eq!(ok.state("test-rule"), DeployState::Active(3), "Started in window 1, locked in at its close, active from window 3");
        assert_ne!(rule_set_id("testnet", &ok), id0, "the rule-set id changes when the deployment activates");
        assert_ne!(run(89, 300).state("test-rule"), DeployState::Active(3), "⛔ 89 % of blocks activated it");
        assert!(!run(89, 300).is_active("test-rule"));
        assert!(!run(100, 150).is_active("test-rule"), "⛔ half the bond activated it");
        let mut late = DeploymentLedger { test_table: Some(vec![d()]), ..DeploymentLedger::default() };
        for score in 0..1_300u64 {
            late.observe_block(score, 1, w, 10, 300, &|_| 0);
        }
        assert_eq!(late.state("test-rule"), DeployState::Failed, "a deployment that never locks in fails at its timeout");
        assert_eq!(late.version_for(1_200), 1, "nothing to signal: the version stays 1");
        let early = DeploymentLedger { test_table: Some(vec![d()]), ..DeploymentLedger::default() };
        assert_eq!(early.version_for(50), 1, "before its start a release does not signal");
        let mut none = DeploymentLedger::default();
        assert!(!none.observe_block(5, 1, w, 10, 300, &|_| 0), "with no deployments the ledger never moves (the launch state)");
        assert_eq!(none, DeploymentLedger::default());
        // a release that knows no deployment still sees others' bits: a window of ≥ 90 % unknown signals sets update_needed
        let mut old = DeploymentLedger::default();
        for score in 0..300u64 {
            old.observe_block(score, VERSION_TOP_BITS | (1 << 9), w, 10, 300, &|_| 0);
        }
        assert!(old.update_needed, "⛔ a release blind to a deployment others signal never says an update is needed");
        let mut quiet = DeploymentLedger::default();
        for score in 0..300u64 {
            quiet.observe_block(score, if score % 10 == 0 { VERSION_TOP_BITS | (1 << 9) } else { 1 }, w, 10, 300, &|_| 0);
        }
        assert!(!quiet.update_needed, "10 % of blocks signalling an unknown bit is not a lock-in");
    }

    /// ⭐⭐ §BR-10 THE EMERGENCY LANE — an emergency deployment locks in after ONE fast window and is active the window after,
    /// while a normal deployment fed the very same blocks and signals still waits for its reward-epoch window. TAMPERS: 80 %
    /// of the fast window's blocks, or half the bond, never lock the emergency deployment in; a FAST signal never counts for a
    /// normal deployment and a normal signal never counts for an emergency one; a normal and a fast signal by one validator in
    /// windows with the same index take two different one-time ids, and a normal signal's id is the id it always had.
    #[test]
    fn an_emergency_deployment_activates_in_one_fast_window_and_a_normal_one_waits_for_its_epoch() {
        let normal = Deployment { name: "normal-rule", bit: 3, start: 0, timeout: 1_000_000, emergency: false };
        let urgent = Deployment { name: "urgent-fix", bit: 4, start: 0, timeout: 1_000_000, emergency: true };
        let v = [7u8; 32];
        let (slow_w, fast_w) = (1_000u64, 10u64);
        let run = |miner_pct: u64, bond_signalled: u128, blocks: u64| -> DeploymentLedger {
            let mut l = DeploymentLedger { test_table: Some(vec![normal, urgent]), ..DeploymentLedger::default() };
            let bond = |set: &BTreeSet<[u8; 32]>| if set.contains(&v) { bond_signalled } else { 0 };
            for score in 0..blocks {
                let signal = (score % 10) * 10 < miner_pct;
                let version = if signal { VERSION_TOP_BITS | (1 << 3) | (1 << 4) } else { 1 };
                l.observe_block(score, version, slow_w, fast_w, 300, &bond);
                l.observe_validator_signal(v, 1 << 3, l.window);
                l.observe_validator_signal(v, (1 << 4) | FAST_SIGNAL, l.fast.window);
            }
            l
        };
        let ok = run(90, 200, 40);
        assert_eq!(ok.state("urgent-fix"), DeployState::Active(3), "Started at fast window 0's close, locked in at 1's, active from 3");
        assert_eq!(ok.state("normal-rule"), DeployState::Defined, "the normal deployment is still inside its first reward-epoch window");
        assert!(!run(80, 300, 40).is_active("urgent-fix"), "⛔ 80 % of the fast window's blocks activated the emergency fix");
        assert!(!run(100, 150, 40).is_active("urgent-fix"), "⛔ half the bond activated the emergency fix");
        // the lanes never cross
        let mut l = DeploymentLedger { test_table: Some(vec![normal, urgent]), test_fast_window: Some(fast_w), ..DeploymentLedger::default() };
        for score in 0..=(slow_w + fast_w) {
            l.observe_block(score, 1, slow_w, fast_w, 300, &|_| 0);
        }
        assert_eq!((l.state("normal-rule"), l.state("urgent-fix")), (DeployState::Started, DeployState::Started), "CALIBRATION: both Started");
        assert!(!l.observe_validator_signal(v, (1 << 3) | FAST_SIGNAL, l.fast.window), "⛔ a FAST signal counted for a normal deployment");
        assert!(!l.observe_validator_signal(v, 1 << 4, l.window), "⛔ a normal signal counted for an emergency deployment");
        assert!(l.observe_validator_signal(v, (1 << 4) | FAST_SIGNAL, l.fast.window), "the fast signal counts for the emergency fix");
        assert!(l.observe_validator_signal(v, 1 << 3, l.window), "the normal signal counts for the normal deployment");
        let nf_normal = crate::deployment_signal_tx::signal_nf(&v, 1 << 3, 5);
        let nf_fast = crate::deployment_signal_tx::signal_nf(&v, (1 << 4) | FAST_SIGNAL, 5);
        assert_ne!(nf_normal, nf_fast, "⛔ a normal and a fast signal in windows with one index share a one-time id");
        assert_eq!(nf_normal, crate::deployment_signal_tx::signal_nf(&v, 1 << 9, 5), "a normal signal's id does not depend on its bits");
        assert!(FAST_WINDOW_TICKS * crate::dag::MESH_TARGET_SPACING_MS >= EMERGENCY_WINDOW_MS && (FAST_WINDOW_TICKS - 1) * crate::dag::MESH_TARGET_SPACING_MS < EMERGENCY_WINDOW_MS, "⛔ the emergency window is not the first whole tick count covering one hour of chain time");
    }
}

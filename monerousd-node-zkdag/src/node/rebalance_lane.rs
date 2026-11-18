// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ SAFE AT SCALE, stage three (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3g.1) — THE REBALANCE LANE AT THE NODE: who carves,
//! for whom, what each custodian signs, and when a custodian frames a step. The doors are the ledger's
//! (`PegLedger::check_vault_carve` / `check_vault_take` / `check_vault_cancel`); the coins are the payout lanes'
//! (`btc_payout`, `xmr_payout`), which read the slot and the receiver's consent from here.
//!
//! THE STEPS, each signed by the one vault whose own openings and sources show what it says:
//!   1. CARVE — a custodian whose own openings show its vault past its authority (`PegLedger::rebalance_part_due`, a pure
//!      function of the vault's openings and its forfeit) signs the carve of that part for the vault the chain's own rule
//!      names (`rebalance_receiver_for`); two thirds of the vault and any of them frames it.
//!   2. CONSENT — a custodian of the receiving vault, holding the part (handed over, `opening_share` kind PART, which
//!      checks the proportion against the slot) and with room for it inside its own vault's authority, signs a consent
//!      naming its vault's current key. A lane statement; no object carries it.
//!   3. THE COINS — the giving vault's payout lanes send the part's coins to the key two thirds of the receiver consented to.
//!   4. TAKE — a custodian of the receiving vault signs once ITS OWN source shows the part's coins at the address the slot
//!      derives; two thirds of the vault (under its bound proof after, or with the whole set) and any of them frames it.
//!   5. CANCEL — a custodian of the giving vault whose own lanes signed no coin move for the slot signs, one rotation day
//!      after the carve; two thirds frame it.
//! SAFE AT SCALE: every statement is one vault's (a take with no bound proof: the whole set's, only while it fits the object);
//! a node keeps book entries only for statements its own vault is party to and relays the rest once (`REBALANCE_RELAY_RING`).
//! AI RESISTANT: every statement a custodian signs is its own derivation from its own chain, openings and sources; a
//! persuasive message gains nothing, and a lying prover's step is refused by its door.

use super::*;
use crate::peg::{LedgerOpening, PegLedger, RebalancePost, BRIDGE_LEDGERS};
use crate::psm::BondQuorum;
use crate::vault_rebalance_tx::{RebalanceStatement, VaultRebalance, VaultRebalanceHeader, VaultRebalanceSig, MAX_SIGS};

/// The rebalance signatures a node relays for vaults it is not party to, by digest: re-gossiped once each.
pub const REBALANCE_RELAY_RING: usize = 1_024;

/// What one ledger kind of a step is proven from: a carve's part values, or the part opening a take or a cancel adds.
#[derive(Clone, Copy, Debug)]
enum StepPart {
    Carve((u128, u128)),
    Add(LedgerOpening),
}

/// ⭐ WHAT A REBALANCE STEP IS PROVEN FROM (`Node::rebalance_ready_to_frame`): gathered under the node lock, proven on a worker
/// thread. `vault` is the vault whose ledgers the step moves (the giver for a carve or a cancel, the receiver for a take).
/// O1-FOOTPRINT-REVIEWED: one copy of the peg ledger (constant size) and at most `CUSTODY_LEDGER_KINDS.len()` openings, alive
/// for one proving job.
pub struct RebalanceProveInputs {
    peg: PegLedger,
    pub header: VaultRebalanceHeader,
    vault: u32,
    kinds: Vec<(u32, LedgerOpening, StepPart)>,
    /// a take: the receiving vault's two bridge openings now ([`BRIDGE_LEDGERS`] order) — its bound is proven over them after
    bridge_now: Option<[LedgerOpening; 2]>,
    forfeit: Option<u128>,
}

impl RebalanceProveInputs {
    /// The step with its signature list EMPTY: two sum proofs per ledger kind, and a take's bound proof when every leg is a
    /// bridge ledger's and the receiving vault stands inside its authority after (else no ride bytes: the whole set signs).
    /// cons: two sum proofs per kind and a take's ride (seconds each) — why this runs off the node lock.
    #[must_use]
    pub fn prove(self) -> Option<VaultRebalance> {
        let from = self.header.from();
        let mut legs = Vec::with_capacity(self.kinds.len());
        let mut after_bridge = self.bridge_now;
        for (asset, open, part) in &self.kinds {
            let (leg, after) = match part {
                StepPart::Carve(p) => {
                    let (leg, _, after) = self.peg.prove_vault_carve_leg(from, *asset, *open, *p)?;
                    (leg, after)
                }
                StepPart::Add(p) => self.peg.prove_vault_part_added_leg(from, self.vault, *asset, *open, *p)?,
            };
            if let (Some(b), Some(i)) = (after_bridge.as_mut(), BRIDGE_LEDGERS.iter().position(|a| a == asset)) {
                b[i] = after;
            }
            legs.push(leg);
        }
        if legs.is_empty() {
            return None;
        }
        let ride = match (self.header, after_bridge, self.forfeit) {
            (VaultRebalanceHeader::Take { .. }, Some(after), Some(f)) if legs.iter().all(|l| BRIDGE_LEDGERS.contains(&l.asset)) => {
                self.peg.prove_vault_ride(self.vault, f, &after).map(|r| r.encode()).unwrap_or_default()
            }
            _ => Vec::new(),
        };
        Some(VaultRebalance { header: self.header, legs, ride, sigs: Vec::new() })
    }
}

fn commits(o: LedgerOpening) -> crate::peg::LedgerPair {
    PegLedger::commits_of_opening(o.0, o.1, o.2, o.3)
}

/// The pairs after a step that adds a part to a ledger, from `(kind, the ledger's opening now, the part)` per kind.
fn added_posts(parts: &[(u32, LedgerOpening, LedgerOpening)]) -> Option<Vec<RebalancePost>> {
    parts.iter().map(|(a, now, p)| Some((*a, None, commits(PegLedger::receiver_opening_after_rebalance(*now, *p)?)))).collect()
}

impl Node {
    /// ⭐ THE VAULT A CARVE OUT OF `from` IS FOR — the chain's own rule, so every custodian of the giving vault names the same
    /// one: the other vaults in seat order, rotated by one each rotation day (`vault_key_window_ticks` of the finalized block's chain tick, so a
    /// part nobody took and its giver cancelled goes to the next vault the next day), the first that has at least half its
    /// seats filled (it can sign its take alone), is named by no other part at rest and has none of its own out (a vault
    /// with a part out carries nothing on its own word, so it could not take alone), and is in no merge.
    /// CACHE-ONLY: read from the chain-derived seats, slots and merge rule; the carve door holds what matters.
    pub(crate) fn rebalance_receiver_for(&self, from: u32) -> Option<u32> {
        let vaults = self.validators.custody_vaults();
        let n = u64::try_from(vaults.len()).ok()?;
        if n <= 1 {
            return None;
        }
        // A-F60: a day is a time — the final block's chain tick, never its height read at an assumed pace. G5 (2026-11-17): on the
        // FINALITY OVERLAY's clock (`payout_final_time_ms`: vote-final OR 64 levels deep), so a finality stall never freezes the day
        let day = (self.payout_final_time_ms() / crate::dag::MESH_TARGET_SPACING_MS) / self.vault_key_window_ticks().max(1);
        let merging = self.vault_merge_due();
        (0..n - 1)
            .map(|k| (u64::from(from) + 1 + (day + k) % (n - 1)) % n)
            .filter_map(|v| u32::try_from(v).ok())
            .find(|v| {
                *v != from
                    && vaults[*v as usize].len() >= crate::custody_vaults::VAULT_MIN
                    && !self.peg.vault_parts_all().any(|(g, p)| p.into == *v || g == *v)
                    && !merging.is_some_and(|(f, i)| f == *v || i == *v)
            })
    }

    /// ⭐ THE CARVE THIS CUSTODIAN'S CHAIN AND OPENINGS SAY IS DUE out of its own vault: `(from, into, per bridge kind (kind,
    /// its own opening, the part))`. `None` while the vault stands inside its authority, has a part at rest, is in a merge, or
    /// this custodian does not open both bridge ledgers.
    pub(crate) fn rebalance_carve_due(&self) -> Option<(u32, u32, Vec<(u32, LedgerOpening, (u128, u128))>)> {
        self.custodian_id()?;
        let from = self.vault_here();
        if self.peg.vault_part(from).is_some() || self.vault_merge_due().is_some_and(|(f, i)| f == from || i == from) {
            return None;
        }
        let open = self.fresh_bridge_openings()?;
        let (_, forfeit) = self.validators.vault(from)?;
        let parts = PegLedger::rebalance_part_due(&open, self.peg.vault_authority_usdm(forfeit)?)?;
        let into = self.rebalance_receiver_for(from)?;
        let legs: Vec<(u32, LedgerOpening, (u128, u128))> = BRIDGE_LEDGERS
            .iter()
            .zip(open)
            .zip(parts)
            .filter(|((a, _), p)| *p != (0, 0) && self.peg.vault_ledger_moved(from, **a))
            .map(|((a, o), p)| (*a, o, p))
            .collect();
        (!legs.is_empty()).then_some((from, into, legs))
    }

    fn rebalance_carve_posts(&self) -> Option<(u32, u32, Vec<RebalancePost>)> {
        let (from, into, legs) = self.rebalance_carve_due()?;
        let posts = legs
            .iter()
            .map(|(a, o, p)| {
                let (part, after) = PegLedger::giver_opening_after_rebalance(*o, *p)?;
                Some((*a, Some(commits(part)), commits(after)))
            })
            .collect::<Option<Vec<_>>>()?;
        Some((from, into, posts))
    }

    /// `(kind, this custodian's opening now, the part)` for every leg of vault `from`'s slot, when the slot is FOR this
    /// custodian's vault and it holds the part it was handed.
    fn rebalance_take_parts(&self, from: u32) -> Option<Vec<(u32, LedgerOpening, LedgerOpening)>> {
        let slot = self.peg.vault_part(from)?;
        if self.custodian_id().is_none() || slot.into != self.vault_here() {
            return None;
        }
        slot.legs.iter().map(|l| Some((l.asset, self.fresh_opening_for_asset(l.asset)?, self.rebalance_held_opening(Self::REBALANCE_IN, l.asset, l.part)?))).collect()
    }

    /// The same for this custodian's OWN vault's slot, with the part it carved (a cancel adds it back).
    fn rebalance_cancel_parts(&self) -> Option<Vec<(u32, LedgerOpening, LedgerOpening)>> {
        self.custodian_id()?;
        let slot = self.peg.vault_part(self.vault_here())?;
        slot.legs.iter().map(|l| Some((l.asset, self.fresh_opening_for_asset(l.asset)?, self.rebalance_held_opening(Self::REBALANCE_PART, l.asset, l.part)?))).collect()
    }

    /// Does this custodian's vault stand inside its own authority with vault `from`'s part added (its own openings and the
    /// part it was handed)? What it consents on.
    fn rebalance_room_for(&self, from: u32) -> bool {
        let (Some(parts), Some(open)) = (self.rebalance_take_parts(from), self.fresh_bridge_openings()) else { return false };
        let Some(authority) = self.validators.vault(self.vault_here()).and_then(|(_, f)| self.peg.vault_authority_usdm(f)) else { return false };
        let added: u128 = parts.iter().filter(|(a, ..)| BRIDGE_LEDGERS.contains(a)).map(|(_, _, p)| p.2).sum();
        open[0].2.saturating_add(open[1].2).saturating_add(added) <= authority
    }

    /// The part's opening this custodian holds of vault `from`'s slot for ledger `asset` — the one it carved (its own vault's
    /// slot) or the one it was handed (a slot for its vault). What its coin lanes read the amount from.
    pub(crate) fn rebalance_part_held(&self, from: u32, asset: u32) -> Option<LedgerOpening> {
        let slot = self.peg.vault_part(from)?;
        let leg = slot.legs.iter().find(|l| l.asset == asset)?;
        let key = if self.custodian_id().is_some() && self.vault_here() == from { Self::REBALANCE_PART } else { Self::REBALANCE_IN };
        self.rebalance_held_opening(key, asset, leg.part)
    }

    /// The digest the coins of vault `from`'s slot are sent under: the slot's own (`PegLedger::vault_part_digest`), so the
    /// address on Bitcoin and the payment id on Monero are derived by both vaults from the chain alone, and differ per part.
    pub(crate) fn rebalance_coin_seed(&self, from: u32, chain: &str) -> Option<[u8; 32]> {
        self.peg.vault_part(from)?;
        let mut h = blake3::Hasher::new_derive_key("musdm.rebalance.coin-seed.v1");
        h.update(chain.as_bytes());
        h.update(&self.peg.vault_part_digest(from));
        Some(*h.finalize().as_bytes())
    }

    /// ⭐ THE KEY THE RECEIVING VAULT CONSENTED TO for vault `from`'s part: a key of that vault the chain records alive, named
    /// by a consent two thirds of the receiving vault signed over this node's own chain's slot. The giving vault's coin lanes
    /// send only to it (and only while it is the receiver's current key: `rebalance_send_key`); the receiving vault's lanes
    /// look for the coins under it.
    /// CACHE-ONLY: read from this node's own book and chain; it decides only what THIS custodian signs.
    pub(crate) fn rebalance_consented_key(&self, from: u32) -> Option<crate::peg::VaultKeyRow> {
        let slot = self.peg.vault_part(from)?;
        let (q, _) = self.validators.vault(slot.into)?;
        let verifier = crate::pqauth::MlDsaVerifier;
        self.rebalance_book
            .values()
            .filter_map(|(st, msg, atts)| match st {
                RebalanceStatement::Consent { from: f, key_since_tick } if *f == from => Some((*key_since_tick, msg, atts)),
                _ => None,
            })
            .filter(|(_, msg, atts)| crate::peg::threshold_ok(&q, &verifier, msg, atts))
            .find_map(|(since, _, _)| self.peg.vault_keys(slot.into).iter().find(|k| k.since_tick == since).cloned())
    }

    /// The consented key while it is the receiving vault's CURRENT key — what a giving custodian sends a part's coins to.
    pub(crate) fn rebalance_send_key(&self, from: u32) -> Option<crate::peg::VaultKeyRow> {
        let k = self.rebalance_consented_key(from)?;
        let into = self.peg.vault_part(from)?.into;
        (self.peg.vault_key_current(into).map(|c| c.since_tick) == Some(k.since_tick)).then_some(k)
    }

    /// ⭐ THIS CUSTODIAN'S OWN REBALANCE SIGNATURES, each over what its own chain, openings and sources say:
    ///   • the CARVE its vault owes (`rebalance_carve_due`);
    ///   • the CANCEL of its vault's slot, a rotation day after the carve, only when `moved(from)` says its own coin lanes
    ///     signed no move for the slot;
    ///   • for a slot FOR its vault: the CONSENT (it holds the part and has room for it, its vault is in no merge), and the
    ///     TAKE once `arrived(from, asset)` says its own source shows the part's coins for every leg.
    /// Empty unless `pk` is this node's own custody identity.
    /// CACHE-ONLY: forms statements from chain state and this custodian's own openings; the doors decide at the fold.
    #[must_use]
    pub fn own_rebalance_sigs(&self, pk: &[u8], sk: &[u8], arrived: &dyn Fn(u32, u32) -> bool, moved: &dyn Fn(u32) -> bool) -> Vec<VaultRebalanceSig> {
        let mut out = Vec::new();
        if self.custodian_id() != Some(crate::pqauth::pubkey_id(pk)) {
            return out;
        }
        let here = self.vault_here();
        let mut push = |stmt: RebalanceStatement, msg: Vec<u8>| {
            if let Some(sig) = crate::pqauth::ml_dsa_sign(&msg, sk) {
                out.push(VaultRebalanceSig { stmt, pubkey: pk.to_vec(), sig });
            }
        };
        if let Some((from, into, posts)) = self.rebalance_carve_posts() {
            let msg = self.peg.vault_carve_msg(from, into, &posts);
            push(RebalanceStatement::Carve { from, into, posts }, msg);
        }
        // A-F60: the cancel's wait is a time, read on the chain tick at the tip
        let tick = self.chain_tick();
        if let Some(slot) = self.peg.vault_part(here) {
            if tick >= slot.opened_tick.saturating_add(self.vault_key_window_ticks()) && !moved(here) {
                if let Some(posts) = self.rebalance_cancel_parts().as_deref().and_then(added_posts) {
                    let msg = self.peg.vault_cancel_msg(here, &posts);
                    push(RebalanceStatement::Cancel { from: here, posts }, msg);
                }
            }
        }
        // a vault in a merge, or with a part of its own out, consents to no part: it could not take one alone
        let merging = self.vault_merge_due().is_some_and(|(f, i)| f == here || i == here) || self.peg.vault_part(here).is_some();
        let incoming: Vec<(u32, crate::peg::VaultPart)> = self.peg.vault_parts_all().filter(|(_, p)| p.into == here).map(|(f, p)| (f, p.clone())).collect();
        for (from, slot) in incoming {
            if let Some(key) = self.peg.vault_key_current(here).filter(|_| !merging && self.rebalance_room_for(from)) {
                let msg = self.peg.vault_part_consent_msg(from, key.since_tick);
                push(RebalanceStatement::Consent { from, key_since_tick: key.since_tick }, msg);
            }
            if slot.legs.iter().all(|l| arrived(from, l.asset)) {
                if let Some(posts) = self.rebalance_take_parts(from).as_deref().and_then(added_posts) {
                    let msg = self.peg.vault_take_msg(from, &posts);
                    push(RebalanceStatement::Take { from, posts }, msg);
                }
            }
        }
        out
    }

    /// The message a rebalance statement's signers sign, formed from THIS node's chain — `None` for a statement of a slot
    /// this chain does not hold (or, for a carve, a vault whose slot is taken). The one read the gatherer and framer share.
    fn rebalance_sig_msg(&self, s: &RebalanceStatement) -> Option<Vec<u8>> {
        match s {
            RebalanceStatement::Carve { from, into, posts } => self.peg.vault_part(*from).is_none().then(|| self.peg.vault_carve_msg(*from, *into, posts)),
            RebalanceStatement::Consent { from, key_since_tick } => {
                let into = self.peg.vault_part(*from)?.into;
                self.peg.vault_keys(into).iter().any(|k| k.since_tick == *key_since_tick).then(|| self.peg.vault_part_consent_msg(*from, *key_since_tick))
            }
            RebalanceStatement::Take { from, posts } => self.peg.vault_part(*from).map(|_| self.peg.vault_take_msg(*from, posts)),
            RebalanceStatement::Cancel { from, posts } => self.peg.vault_part(*from).map(|_| self.peg.vault_cancel_msg(*from, posts)),
        }
    }

    /// May `signer` sign `s`? A carve or a cancel: a custodian seated in the giving vault. A consent: one seated in the vault
    /// the slot is for. A take: any bonded custodian (with no bound proof the whole set's two thirds sign it; the door tallies).
    fn rebalance_signer_allowed(&self, s: &RebalanceStatement, signer: &[u8; 32]) -> bool {
        let seated = |v: u32| self.vault_seats_sorted(v).binary_search(signer).is_ok();
        match s {
            RebalanceStatement::Carve { from, .. } | RebalanceStatement::Cancel { from, .. } => seated(*from),
            RebalanceStatement::Consent { from, .. } => self.peg.vault_part(*from).is_some_and(|p| seated(p.into)),
            RebalanceStatement::Take { .. } => self.validators.is_bonded_custodian(signer),
        }
    }

    /// Is THIS custodian's vault party to `s` — the statements its own book keeps (the rest it relays once)?
    fn rebalance_party(&self, s: &RebalanceStatement) -> bool {
        if self.custodian_id().is_none() {
            return false;
        }
        let here = self.vault_here();
        let into = self.peg.vault_part(s.from()).map(|p| p.into);
        match s {
            RebalanceStatement::Carve { from, .. } | RebalanceStatement::Cancel { from, .. } => *from == here,
            RebalanceStatement::Consent { from, .. } => *from == here || into == Some(here),
            RebalanceStatement::Take { .. } => into == Some(here),
        }
    }

    /// Drop every book entry whose message no longer forms the same against this node's chain, or that this node is no
    /// longer party to (a slot closed, a ledger moved, a seat changed).
    fn prune_rebalance_book(&mut self) {
        let book = std::mem::take(&mut self.rebalance_book);
        self.rebalance_book = book.into_iter().filter(|(_, (st, msg, _))| self.rebalance_party(st) && self.rebalance_sig_msg(st).as_deref() == Some(msg.as_slice())).collect();
    }

    /// ⭐ GATHER ONE CUSTODIAN'S REBALANCE SIGNATURE from the lane. Verified over the message THIS node's chain forms (never the
    /// wire's) and counted only for a signer the chain lets sign that statement. Kept when this node's own vault is party to
    /// it (one statement per kind and giving vault per signer: a newer one replaces it); otherwise relayed once. `true` when
    /// it is NEW — the re-gossip signal.
    /// §9.6 and the pillar answers: on `vault_rebalance_tx::VaultRebalanceSig`.
    pub fn rebalance_sig_ingest(&mut self, s: &VaultRebalanceSig, verifier: &dyn crate::pqauth::PqVerifier) -> bool {
        let signer = crate::pqauth::pubkey_id(&s.pubkey);
        if !self.rebalance_signer_allowed(&s.stmt, &signer) {
            return false;
        }
        let Some(msg) = self.rebalance_sig_msg(&s.stmt) else { return false };
        if !verifier.verify(&s.pubkey, &msg, &s.sig) {
            return false;
        }
        if !self.rebalance_party(&s.stmt) {
            let d = *blake3::hash(&s.wire()).as_bytes();
            if self.rebalance_relayed.contains(&d) {
                return false;
            }
            if self.rebalance_relayed.len() >= REBALANCE_RELAY_RING {
                self.rebalance_relayed.pop_front();
            }
            self.rebalance_relayed.push_back(d);
            return true;
        }
        self.prune_rebalance_book();
        let key = s.stmt.digest();
        if self.rebalance_book.get(&key).is_some_and(|(_, _, atts)| atts.iter().any(|a| a.pubkey == s.pubkey) || atts.len() >= MAX_SIGS) {
            return false; // already gathered, or the object's list is full
        }
        let kind = std::mem::discriminant(&s.stmt);
        for (k, (st, _, atts)) in self.rebalance_book.iter_mut() {
            if *k != key && std::mem::discriminant(st) == kind && st.from() == s.stmt.from() {
                atts.retain(|a| a.pubkey != s.pubkey);
            }
        }
        self.rebalance_book.retain(|k, (_, _, atts)| *k == key || !atts.is_empty());
        let entry = self.rebalance_book.entry(key).or_insert_with(|| (s.stmt.clone(), msg, Vec::new()));
        entry.2.push(crate::psm::MintAttestor { pubkey: s.pubkey.clone(), sig: s.sig.clone() });
        true
    }

    fn rebalance_entry_met(&self, stmt: &RebalanceStatement, vault: u32, verifier: &dyn crate::pqauth::PqVerifier) -> Option<Vec<crate::psm::MintAttestor>> {
        let (_, msg, atts) = self.rebalance_book.get(&stmt.digest())?;
        let (q, _) = self.validators.vault(vault)?;
        crate::peg::threshold_ok(&q, verifier, msg, atts).then(|| atts.clone())
    }

    /// ⭐ A REBALANCE STEP THIS CUSTODIAN CAN FRAME: the statement its own openings derive reaches two thirds of the vault that
    /// signs it (the giver for a carve or a cancel, the receiver for a take). Returns the signatures and what the proofs are
    /// made from (on a worker thread); the runtime frames only a step its door would take (a take with no bound proof also
    /// needs the whole set; a cancel, its rotation day).
    pub fn rebalance_ready_to_frame(&mut self, verifier: &dyn crate::pqauth::PqVerifier) -> Option<(Vec<crate::psm::MintAttestor>, RebalanceProveInputs)> {
        self.custodian_id()?;
        self.prune_rebalance_book();
        let here = self.vault_here();
        if let Some((from, into, posts)) = self.rebalance_carve_posts() {
            if let Some(sigs) = self.rebalance_entry_met(&RebalanceStatement::Carve { from, into, posts }, from, verifier) {
                let (_, _, legs) = self.rebalance_carve_due()?;
                let kinds = legs.into_iter().map(|(a, o, p)| (a, o, StepPart::Carve(p))).collect();
                return Some((sigs, RebalanceProveInputs { peg: self.peg.clone(), header: VaultRebalanceHeader::Carve { from, into }, vault: from, kinds, bridge_now: None, forfeit: None }));
            }
        }
        let incoming: Vec<u32> = self.peg.vault_parts_all().filter(|(_, p)| p.into == here).map(|(f, _)| f).collect();
        for from in incoming {
            let Some(parts) = self.rebalance_take_parts(from) else { continue };
            let Some(posts) = added_posts(&parts) else { continue };
            if let Some(sigs) = self.rebalance_entry_met(&RebalanceStatement::Take { from, posts }, here, verifier) {
                let forfeit = self.validators.vault(here).map(|(_, f)| f);
                let kinds = parts.into_iter().map(|(a, o, p)| (a, o, StepPart::Add(p))).collect();
                let inputs = RebalanceProveInputs { peg: self.peg.clone(), header: VaultRebalanceHeader::Take { from }, vault: here, kinds, bridge_now: self.fresh_bridge_openings(), forfeit };
                return Some((sigs, inputs));
            }
        }
        if let Some(parts) = self.rebalance_cancel_parts() {
            let posts = added_posts(&parts)?;
            if let Some(sigs) = self.rebalance_entry_met(&RebalanceStatement::Cancel { from: here, posts }, here, verifier) {
                let kinds = parts.into_iter().map(|(a, o, p)| (a, o, StepPart::Add(p))).collect();
                return Some((sigs, RebalanceProveInputs { peg: self.peg.clone(), header: VaultRebalanceHeader::Cancel { from: here }, vault: here, kinds, bridge_now: None, forfeit: None }));
            }
        }
        None
    }

    /// Would the door take this proven step on THIS node's chain now (a cancel at the tip's chain tick — a lower bound on
    /// the carrying block's, whose median time past is at least the tip's)? The framer's one check before it publishes.
    #[must_use]
    pub fn rebalance_door_takes(&self, r: &VaultRebalance) -> crate::peg::PegOutcome {
        let verifier = crate::pqauth::MlDsaVerifier;
        match r.header {
            VaultRebalanceHeader::Carve { from, into } => self.peg.check_vault_carve(from, into, &r.legs, &self.validators, &verifier, &r.sigs),
            VaultRebalanceHeader::Take { from } => self.peg.check_vault_take(from, &r.legs, &r.ride, &self.validators, &verifier, &r.sigs),
            VaultRebalanceHeader::Cancel { from } => {
                self.peg.check_vault_cancel(from, &r.legs, self.chain_tick(), self.vault_key_window_ticks(), &self.validators, &verifier, &r.sigs)
            }
        }
    }
}

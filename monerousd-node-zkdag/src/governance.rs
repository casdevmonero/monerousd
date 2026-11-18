// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Bicameral, anti-capture governance of the runtime-tunable consensus parameters.
//!
//! MonerousD's consensus knobs (DAG width, block spacing, k) are governance-tunable AT RUNTIME with
//! no new chain and no node restart ([`crate::params::ChainParams`]). This module is the gate that
//! decides WHEN a retune enacts: a parameter change must win a super-majority in BOTH chambers —
//! **miners** (hashpower) AND **validators** (bonded stake). Neither chamber can move consensus
//! alone, so neither hashpower capture nor a stake buyout can unilaterally change the rules.
//!
//! Chamber weights come from real chain state — the validator chamber's total is the bonded stake
//! ([`crate::validator::ValidatorSet::total_bond`]); the miner chamber's total is the recent
//! block-production weight — and are passed in at evaluation time. A vote is a consensus-validated
//! record (its authenticity, the voter's PQ signature, is checked at the tx/consensus edge, like any
//! chain record); this module enforces the (real) bicameral-threshold arithmetic that record feeds.
//!
//! What is DELIBERATELY not tunable: network-privacy invariants (cell size, cover rate) are fixed
//! constants in [`crate::net`] and can NEVER be proposed here — privacy is 100% by construction,
//! never a governance choice ([[feedback_network_privacy_fixed_by_default]] in project memory).

use std::collections::HashMap;

use crate::hash::Hash32;
use crate::params::{ChainParams, ParamError};

/// Enactment threshold = 2/3 of EACH chamber's total weight.
pub const GOV_NUMERATOR: u128 = 2;
pub const GOV_DENOMINATOR: u128 = 3;

// ============================================================================
// CONSTITUTIONAL INVARIANTS (user 2026-07-12): MonerousD is a MONERO-ETHOS,
// COMMUNITY-GOVERNED project — the constitution locks the ABSOLUTE MINIMUM and
// leaves EVERYTHING ELSE to the community's free vote. Only THREE narrow lines
// are un-crossable, and only where crossing one would let an adversary STEAL
// or TRAP people's value:
//   1. never LESS PRIVATE — already impossible: no privacy knob is a
//      `ParamChange` (cell size, cover rate, is_zk, decoys are fixed constants),
//      so privacy cannot even be proposed. Nothing to enforce here.
//   2. never MORE EXCLUSIONARY — no permissioning / allow-list knob exists; the
//      only exclusion vector is a confiscatory exit fee, so a generous fee
//      ceiling guards the freedom to exit.
//   3. never LESS SECURE — two floors only: peg SOLVENCY (anti-rug mint ratio)
//      and SLASHING integrity (a positive unbond delay).
// Every other consensus + economic knob — DAG width, block spacing, reward APR,
// reward epoch, unbond length above the floor — is the community's FREE vote
// inside the existing param-range checks, DELIBERATELY not locked. (DAG width
// is a throughput/latency tradeoff, not a safety line: a narrower graph is
// still fully secure, so the community owns that choice.) A change crossing a
// real line is rejected at propose AND can never enact (ANY vote count) — so a
// captured super-majority (both chambers) still cannot cross these three lines.
// ============================================================================

/// Backing floor: the HARD constitutional minimum PSM collateralization. Governance may VOTE the mint ratio
/// anywhere at or above this floor (security without over-restriction — 150% is the default *target*, not a
/// lock; e.g. the community can lower it to 120%), but NEVER below 110% — a ratio under 110% leaves too thin
/// a solvency buffer to keep every minted USDm fully collateralized, so the peg could break; that is
/// unconstitutional.
pub const MINT_RATIO_BACKING_FLOOR_BPS: u32 = 11_000;
/// A staked bond must carry a positive unbond delay: a zero-delay exit lets an equivocator withdraw before
/// its double-sign is slashed (nothing-at-stake), defeating slashing entirely. Governance may set the lock
/// to ANY length of one block or more — this floor only rules out the zero that would nullify slashing.
pub const STAKE_LOCK_MIN_BLOCKS: u64 = 1;
/// Anti-confiscation cap: a withdrawal fee above this would trap ordinary users' funds (pay-to-exit = a rug
/// in disguise). Governance may set a fee band anywhere up to this generous ceiling — freedom to exit is never
/// votable away — but never past it.
pub const WITHDRAW_FEE_EXCLUSION_CEILING_BPS: u32 = 5_000;

/// A proposed change that would cross a constitutional line. It can never be opened or enacted.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConstitutionalViolation {
    /// Would make the chain LESS SECURE (weaker consensus / under-collateralized / slashing-evadable).
    #[error("unconstitutional — would make MonerousD LESS SECURE: {0}")]
    LessSecure(&'static str),
    /// Would make the chain LESS PRIVATE. (No governance knob touches privacy — cell size, cover rate,
    /// is_zk, decoys are fixed constants in `crate::net`/the circuit and are NOT `ParamChange` variants —
    /// so this is unreachable by construction; kept so the invariant is named + total.)
    #[error("unconstitutional — would make MonerousD LESS PRIVATE: {0}")]
    LessPrivate(&'static str),
    /// Would make the chain MORE EXCLUSIONARY (raise a barrier that prices out ordinary users).
    #[error("unconstitutional — would make MonerousD MORE EXCLUSIONARY: {0}")]
    Exclusionary(&'static str),
}

/// A proposed change to a governance-tunable parameter. Only runtime-tunable knobs appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamChange {
    SetDagWidth(usize),
    SetTargetSpacingMs(u64),
    /// PSM mint collateral ratio (basis points) — the community's chosen over-collateralization for Buy-USDm.
    SetMintRatioBps(u32),
    /// Staking reward APR (basis points/yr) — the target reward rate stakers earn from the reserve surplus.
    SetStakeRewardAprBps(u32),
    /// Stake maturity / unbond-delay (blocks) — how long a staked note is locked.
    SetStakeLockBlocks(u64),
    /// Redemption withdrawal-fee band (min_bps, max_bps) — the convex anti-drain fee floor + ceiling.
    SetWithdrawFeeBand(u32, u32),
    /// Reward-epoch length (blocks) — how often the reserve-yield surplus is distributed into the reward indices;
    /// 0 pauses reward delivery.
    SetRewardEpochBlocks(u64),
    /// PQ-VDF heartbeat length (sequential MinRoot steps per block) — the CONSTANT block-clock the community can
    /// retune (a faster or slower launch cadence) freely within the constitutional anti-outsource floor.
    SetVdfSteps(u64),
}

impl ParamChange {
    fn encode(&self) -> Vec<u8> {
        match self {
            ParamChange::SetDagWidth(w) => {
                let mut v = vec![1u8];
                v.extend_from_slice(&(*w as u64).to_le_bytes());
                v
            }
            ParamChange::SetTargetSpacingMs(ms) => {
                let mut v = vec![2u8];
                v.extend_from_slice(&ms.to_le_bytes());
                v
            }
            ParamChange::SetMintRatioBps(bps) => {
                let mut v = vec![3u8];
                v.extend_from_slice(&(*bps as u64).to_le_bytes());
                v
            }
            ParamChange::SetStakeRewardAprBps(bps) => {
                let mut v = vec![4u8];
                v.extend_from_slice(&(*bps as u64).to_le_bytes());
                v
            }
            ParamChange::SetStakeLockBlocks(b) => {
                let mut v = vec![5u8];
                v.extend_from_slice(&b.to_le_bytes());
                v
            }
            ParamChange::SetWithdrawFeeBand(mn, mx) => {
                let mut v = vec![6u8];
                v.extend_from_slice(&(*mn as u64).to_le_bytes());
                v.extend_from_slice(&(*mx as u64).to_le_bytes());
                v
            }
            ParamChange::SetRewardEpochBlocks(b) => {
                let mut v = vec![7u8];
                v.extend_from_slice(&b.to_le_bytes());
                v
            }
            ParamChange::SetVdfSteps(s) => {
                let mut v = vec![8u8];
                v.extend_from_slice(&s.to_le_bytes());
                v
            }
        }
    }

    /// The deterministic proposal id for this change.
    pub fn id(&self) -> Hash32 {
        Hash32::hash(&self.encode())
    }

    /// Apply this change to a params set — fail-closed via the range checks in [`crate::params`].
    pub fn apply(&self, params: &mut ChainParams) -> Result<(), ParamError> {
        match self {
            ParamChange::SetDagWidth(w) => params.governance_set_dag_width(*w),
            ParamChange::SetTargetSpacingMs(ms) => params.governance_set_target_spacing_ms(*ms),
            ParamChange::SetMintRatioBps(bps) => params.governance_set_mint_ratio_bps(*bps),
            ParamChange::SetStakeRewardAprBps(bps) => {
                params.governance_set_stake_reward_apr_bps(*bps)
            }
            ParamChange::SetStakeLockBlocks(b) => {
                params.governance_set_stake_lock_blocks(*b);
                Ok(())
            }
            ParamChange::SetWithdrawFeeBand(mn, mx) => {
                params.governance_set_withdraw_fee_band(*mn, *mx)
            }
            ParamChange::SetRewardEpochBlocks(b) => {
                params.governance_set_reward_epoch_blocks(*b);
                Ok(())
            }
            ParamChange::SetVdfSteps(s) => params.governance_set_vdf_steps(*s),
        }
    }

    /// CONSTITUTIONAL GATE: reject ONLY the three changes that would let an adversary STEAL or TRAP
    /// people's value — regardless of how many votes they win. Everything else (DAG width, block spacing,
    /// reward APR/epoch, etc.) is the community's free vote, bounded only by the ordinary param-range
    /// checks. Enforced at BOTH propose (rejected at the proposal layer) and enact (impossible to apply),
    /// so an adversarial vote across even a captured super-majority is impossible by construction.
    /// `Ok` = constitutional. Monero-ethos minimal lock: the constitution owns solvency, slashing
    /// integrity, and the freedom to exit — nothing more.
    pub fn constitutional_check(&self) -> Result<(), ConstitutionalViolation> {
        use ConstitutionalViolation::{Exclusionary, LessSecure};
        match *self {
            // SOLVENCY floor — a mint ratio below 110% cannot keep every USDm fully collateralized (peg-break risk).
            ParamChange::SetMintRatioBps(bps) if bps < MINT_RATIO_BACKING_FLOOR_BPS => Err(LessSecure(
                "PSM mint ratio below the 110% backing floor — too thin a solvency buffer risks the peg",
            )),
            // SLASHING integrity — a zero unbond delay lets an equivocator withdraw before it is slashed.
            ParamChange::SetStakeLockBlocks(b) if b < STAKE_LOCK_MIN_BLOCKS => Err(LessSecure(
                "stake lock below the minimum unbond delay — a zero-delay exit lets an equivocator \
                 withdraw before it is slashed (nothing-at-stake)",
            )),
            // FREEDOM TO EXIT — a confiscatory withdrawal fee (or an inverted band) traps ordinary users.
            ParamChange::SetWithdrawFeeBand(mn, mx) if mx > WITHDRAW_FEE_EXCLUSION_CEILING_BPS || mn > mx => {
                Err(Exclusionary(
                    "withdrawal fee above the exclusion ceiling (or an inverted band) — the chain can \
                     never be made pay-to-exit / price ordinary users out",
                ))
            }
            // ANTI-OUTSOURCE floor — the VDF heartbeat is freely retunable (faster/slower cadence), but NEVER below
            // the sequential-work floor: that would erase the anti-outrun / anti-outsource barrier a single fast or
            // captured producer relies on to outrun the interval (a "less secure" capture, impossible by construction).
            ParamChange::SetVdfSteps(s) if s < crate::params::VDF_STEPS_SECURITY_FLOOR => Err(LessSecure(
                "VDF heartbeat below the sequential-work security floor — that erases the anti-outsource barrier",
            )),
            // DAG width, block spacing, reward APR/epoch, stake lock ≥ 1, VDF steps ≥ floor, etc. are DELIBERATELY
            // unlocked — the community owns every throughput / latency / economic tradeoff, subject only to range checks.
            _ => Ok(()),
        }
    }

    /// A readable (kind, value) view for the RPC snapshot the wallet renders.
    pub fn kind_value(&self) -> (&'static str, u64) {
        match self {
            ParamChange::SetDagWidth(w) => ("dag_width", *w as u64),
            ParamChange::SetTargetSpacingMs(ms) => ("target_spacing_ms", *ms),
            ParamChange::SetMintRatioBps(bps) => ("mint_ratio_bps", *bps as u64),
            ParamChange::SetStakeRewardAprBps(bps) => ("stake_reward_apr_bps", *bps as u64),
            ParamChange::SetStakeLockBlocks(b) => ("stake_lock_blocks", *b),
            // The band packs both bounds into one u64 for the (kind,value) wire form: (min<<32)|max.
            ParamChange::SetWithdrawFeeBand(mn, mx) => {
                ("withdraw_fee_band", ((*mn as u64) << 32) | (*mx as u64))
            }
            ParamChange::SetRewardEpochBlocks(b) => ("reward_epoch_blocks", *b),
            ParamChange::SetVdfSteps(s) => ("vdf_steps", *s),
        }
    }

    /// Reconstruct a change from its `(kind, value)` wire form — the SINGLE inverse of [`Self::kind_value`],
    /// shared by BOTH the `/propose_param_change` + `/submit_governance_vote` RPC handlers AND the
    /// [`GovernGossip`] inbound handler, so a gossiped proposal/vote reconstructs to the byte-identical
    /// `ParamChange` (hence the same `id()`) a local RPC would — no divergence. An unknown kind → `None`
    /// (fail-closed: a peer can never inject an unrecognized parameter change).
    pub fn from_kind_value(kind: &str, value: u64) -> Option<ParamChange> {
        match kind {
            "dag_width" => Some(ParamChange::SetDagWidth(value as usize)),
            "target_spacing_ms" => Some(ParamChange::SetTargetSpacingMs(value)),
            "mint_ratio_bps" => Some(ParamChange::SetMintRatioBps(value as u32)),
            "stake_reward_apr_bps" => Some(ParamChange::SetStakeRewardAprBps(value as u32)),
            "stake_lock_blocks" => Some(ParamChange::SetStakeLockBlocks(value)),
            "withdraw_fee_band" => Some(ParamChange::SetWithdrawFeeBand(
                (value >> 32) as u32,
                (value & 0xFFFF_FFFF) as u32,
            )),
            "reward_epoch_blocks" => Some(ParamChange::SetRewardEpochBlocks(value)),
            "vdf_steps" => Some(ParamChange::SetVdfSteps(value)),
            _ => None,
        }
    }
}

/// The two governance chambers. Bicameral by design: neither can enact a change without the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chamber {
    Miners,
    Validators,
}

/// The result of evaluating a proposal against the current chamber totals.
#[derive(Debug, PartialEq, Eq)]
pub enum EnactOutcome {
    /// Both chambers reached the super-majority and the change was applied to the live params.
    Enacted,
    /// The miner chamber is below the 2/3 threshold.
    MinersShort,
    /// The validator chamber is below the 2/3 threshold.
    ValidatorsShort,
    /// Both chambers passed, but the proposed value is out of range — rejected fail-closed.
    Rejected(ParamError),
    /// The change would cross a CONSTITUTIONAL invariant (exclusionary / less private / less secure).
    /// Checked BEFORE the vote threshold, so it can NEVER enact regardless of vote count — a captured
    /// super-majority in both chambers still cannot weaken the protocol. Adversarial votes are
    /// impossible by construction.
    Unconstitutional(ConstitutionalViolation),
}

/// A single open proposal accumulating votes in each chamber.
pub struct Proposal {
    pub id: Hash32,
    pub change: ParamChange,
    miner_votes: HashMap<[u8; 32], u128>,
    validator_votes: HashMap<[u8; 32], u128>,
}

impl Proposal {
    pub fn new(change: ParamChange) -> Self {
        Proposal {
            id: change.id(),
            change,
            miner_votes: HashMap::new(),
            validator_votes: HashMap::new(),
        }
    }

    /// Record a (consensus-validated) vote with the voter's chamber weight. Idempotent per voter. Returns
    /// whether the tally CHANGED — a NEW voter, or the SAME voter at a DIFFERENT weight (e.g. their bond grew).
    /// An identical (voter, weight) re-vote returns false so the gossip layer does NOT re-broadcast it (the
    /// bidirectional governance-vote gossip stays loop-free — an echo dies instead of ping-ponging forever).
    pub fn vote(&mut self, chamber: Chamber, voter: [u8; 32], weight: u128) -> bool {
        let book = match chamber {
            Chamber::Miners => &mut self.miner_votes,
            Chamber::Validators => &mut self.validator_votes,
        };
        book.insert(voter, weight) != Some(weight)
    }

    fn tally(votes: &HashMap<[u8; 32], u128>) -> u128 {
        votes.values().copied().sum()
    }

    /// The current miner-chamber weight tally (for the RPC snapshot the wallet renders).
    pub fn miner_tally(&self) -> u128 {
        Self::tally(&self.miner_votes)
    }

    /// The current validator-chamber weight tally (for the RPC snapshot the wallet renders).
    pub fn validator_tally(&self) -> u128 {
        Self::tally(&self.validator_votes)
    }

    /// weight/total ≥ 2/3  ⟺  weight·3 ≥ 2·total. A zero-weight chamber can never pass (fail-closed).
    fn passes(weight: u128, total: u128) -> bool {
        total > 0 && weight.saturating_mul(GOV_DENOMINATOR) >= GOV_NUMERATOR.saturating_mul(total)
    }

    /// Evaluate against the CURRENT chamber totals and, iff BOTH chambers hit the super-majority,
    /// apply the change to `params` in place. Anti-capture: one chamber alone never enacts.
    pub fn try_enact(
        &self,
        params: &mut ChainParams,
        miner_total: u128,
        validator_total: u128,
    ) -> EnactOutcome {
        // CONSTITUTIONAL GATE FIRST — before votes are even weighed. A change that would make MonerousD
        // exclusionary / less private / less secure can NEVER enact, no matter the vote count. This is
        // what makes adversarial governance impossible by construction: even both chambers at 100% cannot
        // cross a constitutional line.
        if let Err(v) = self.change.constitutional_check() {
            return EnactOutcome::Unconstitutional(v);
        }
        if !Self::passes(Self::tally(&self.miner_votes), miner_total) {
            return EnactOutcome::MinersShort;
        }
        if !Self::passes(Self::tally(&self.validator_votes), validator_total) {
            return EnactOutcome::ValidatorsShort;
        }
        match self.change.apply(params) {
            Ok(()) => EnactOutcome::Enacted,
            Err(e) => EnactOutcome::Rejected(e),
        }
    }
}

/// A node's live set of open governance proposals (mirrored from the chain).
pub struct Governance {
    proposals: HashMap<Hash32, Proposal>,
}

impl Governance {
    pub fn new() -> Self {
        Governance {
            proposals: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.proposals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    /// Open a proposal (idempotent: an identical change maps to the same id). Returns its id, or a
    /// [`ConstitutionalViolation`] if the change would make the chain exclusionary / less private / less
    /// secure — such a proposal is REJECTED at the proposal layer and never opens (so it can't even
    /// accumulate votes, on a local RPC OR a gossiped `ProposalOpen`). The enact gate re-checks it too.
    pub fn propose(&mut self, change: ParamChange) -> Result<Hash32, ConstitutionalViolation> {
        change.constitutional_check()?;
        let id = change.id();
        self.proposals
            .entry(id)
            .or_insert_with(|| Proposal::new(change));
        Ok(id)
    }

    pub fn get(&self, id: &Hash32) -> Option<&Proposal> {
        self.proposals.get(id)
    }

    /// Every open proposal (for the read snapshot the wallet renders — order is unspecified).
    pub fn proposals(&self) -> impl Iterator<Item = &Proposal> {
        self.proposals.values()
    }

    /// Cast a chamber vote on an open proposal. Returns whether the tally CHANGED (a fresh voter or a new
    /// weight) — false if no such proposal OR the identical vote was already recorded, so the gossip layer
    /// re-broadcasts only a genuine change (loop-free).
    pub fn vote(&mut self, id: &Hash32, chamber: Chamber, voter: [u8; 32], weight: u128) -> bool {
        match self.proposals.get_mut(id) {
            Some(p) => p.vote(chamber, voter, weight),
            None => false,
        }
    }

    /// Whether a proposal with this id is currently open (used to gossip a freshly-opened proposal exactly once).
    pub fn has(&self, id: &Hash32) -> bool {
        self.proposals.contains_key(id)
    }

    /// ⛔⛔⛔ EVALUATE ONLY — the read-only twin, and the one production may call.
    ///
    /// `try_enact` below takes `&mut self` and RETIRES the proposal on `Enacted`. Both halves of that are
    /// local mutations on a local reading of the evidence: this node's gossiped votes and its own
    /// `total_bond()`. Two honest nodes therefore retire — and retune — at different heights, or one does
    /// and the other never does, and they then run DIFFERENT RULES. Changing `ChainParams` is changing
    /// the rules, which is stronger than moving value, so the trustless cardinal applies at full force:
    /// a rule change must be a CHAIN OBJECT the block carries, never a local mutation.
    ///
    /// This variant answers the same question — "would both chambers carry it, and is the value in
    /// range" — while touching nothing. `params` is a caller-owned SCRATCH copy that must be discarded.
    /// See `Node::evaluate_param_enactment` and `docs/DB154-COMMITTED-NULLIFIER-ROOT.md` for the block
    /// field that will carry the enactment.
    #[must_use]
    pub fn try_enact_readonly(
        &self,
        id: &Hash32,
        params: &mut ChainParams,
        miner_total: u128,
        validator_total: u128,
    ) -> Option<EnactOutcome> {
        Some(
            self.proposals
                .get(id)?
                .try_enact(params, miner_total, validator_total),
        )
    }

    /// Try to enact a proposal against the current chamber totals. On `Enacted` the change is applied
    /// to `params` and the proposal is retired; otherwise it stays open. Returns None if unknown.
    ///
    /// ⛔ NOT FOR PRODUCTION — this is the APPLY half, and it may only ever be driven by a block that
    /// CARRIES the enacted change (the field does not exist yet; see `try_enact_readonly`). Production
    /// calls the read-only twin. Kept because the apply logic itself is correct and is what the
    /// chain-object path will call once the block carries the enactment.
    pub fn try_enact(
        &mut self,
        id: &Hash32,
        params: &mut ChainParams,
        miner_total: u128,
        validator_total: u128,
    ) -> Option<EnactOutcome> {
        let outcome = self
            .proposals
            .get(id)?
            .try_enact(params, miner_total, validator_total);
        if matches!(outcome, EnactOutcome::Enacted) {
            self.proposals.remove(id);
        }
        Some(outcome)
    }
}

impl Default for Governance {
    fn default() -> Self {
        Self::new()
    }
}

/// A gossiped governance record — the wire form the governance directory REPLICATES across the mesh so open
/// proposals AND their bicameral vote tallies CONVERGE (the last public directory to become bidirectional;
/// blocks/txs/sites/finality-votes/names/clues/note-clues already converge). A governance proposal + its votes
/// are chain-anchored consensus state, not a single-node island: a validator on ANY node can see the same open
/// proposals and independently tally the ≥2/3-of-both-chambers super-majority.
///
/// Two variants, each carrying the change's `(kind, value)` so a peer reconstructs the byte-identical
/// [`ParamChange`] (hence the same `id()`) via [`ParamChange::from_kind_value`]:
/// - `ProposalOpen` — a permissionless proposal opening (the anti-capture gate is at ENACT, never at propose),
///   re-gossiped ONLY when freshly inserted (dedup by id).
/// - `Vote` — a VALIDATOR-chamber vote carrying the voter's ML-DSA `pubkey` + `sig` over
///   [`crate::pqauth::governance_vote_msg`]`(id, 2)`, so a receiver re-runs the SAME authenticated adopt
///   (verify sig → voter id = H(pubkey) → credit the voter's LIVE bonded weight) before recording — no party
///   can cast another's vote or inflate their weight — and re-gossips ONLY a vote that changed the tally.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernGossip {
    ProposalOpen {
        kind: String,
        value: u64,
    },
    Vote {
        kind: String,
        value: u64,
        voter_pubkey: Vec<u8>,
        sig: Vec<u8>,
    },
}

impl GovernGossip {
    /// Postcard wire bytes (the [`crate::protocol::WireMsg::Govern`] payload).
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Decode a received frame; a corrupt/truncated one returns `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<GovernGossip> {
        crate::chain_object::decode_exact(bytes)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn who(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn one_chamber_alone_cannot_capture_consensus() {
        let mut params = ChainParams::default();
        let mut gov = Governance::new();
        // three equal miners (total 9000) and three equal validators (total 9000).
        let (miner_total, validator_total) = (9000u128, 9000u128);
        let id = gov
            .propose(ParamChange::SetDagWidth(64))
            .expect("constitutional");

        // miners reach 2/3 (2 of 3), validators silent -> NOT enacted (anti-capture).
        gov.vote(&id, Chamber::Miners, who(1), 3000);
        gov.vote(&id, Chamber::Miners, who(2), 3000);
        assert_eq!(
            gov.try_enact(&id, &mut params, miner_total, validator_total),
            Some(EnactOutcome::ValidatorsShort)
        );
        assert_eq!(params.dag_width, 32, "no chamber alone changes the params");

        // validators now reach 2/3 as well -> enacted, width retunes at runtime, k tracks it.
        gov.vote(&id, Chamber::Validators, who(1), 3000);
        gov.vote(&id, Chamber::Validators, who(2), 3000);
        assert_eq!(
            gov.try_enact(&id, &mut params, miner_total, validator_total),
            Some(EnactOutcome::Enacted)
        );
        assert_eq!(params.dag_width, 64);
        assert_eq!(params.ghostdag_k, 64);
        // the enacted proposal is retired.
        assert!(gov.get(&id).is_none());
    }

    #[test]
    fn duplicate_votes_are_idempotent_and_spacing_retunes() {
        let mut params = ChainParams::default();
        let mut gov = Governance::new();
        let id = gov
            .propose(ParamChange::SetTargetSpacingMs(500))
            .expect("constitutional");
        // a single miner keeps voting — weight counts ONCE (2000 of a 6000 total = 1/3, short).
        gov.vote(&id, Chamber::Miners, who(1), 2000);
        gov.vote(&id, Chamber::Miners, who(1), 2000);
        assert_eq!(
            gov.try_enact(&id, &mut params, 6000, 6000),
            Some(EnactOutcome::MinersShort)
        );
        // a second distinct miner + two validators push both chambers to 2/3.
        gov.vote(&id, Chamber::Miners, who(2), 2000);
        gov.vote(&id, Chamber::Validators, who(1), 2000);
        gov.vote(&id, Chamber::Validators, who(2), 2000);
        assert_eq!(
            gov.try_enact(&id, &mut params, 6000, 6000),
            Some(EnactOutcome::Enacted)
        );
        assert_eq!(params.target_spacing_ms, 500);
    }

    #[test]
    fn reward_epoch_blocks_retunes_via_bicameral_governance_and_survives_gossip_roundtrip() {
        let mut params = ChainParams::default();
        assert_eq!(
            params.reward_epoch_blocks,
            crate::params::REWARD_EPOCH_BLOCKS_DEFAULT
        );
        let mut gov = Governance::new();
        // A SHORTER reward epoch (600 blocks) distributes the reserve-yield surplus into the reward indices more
        // often — the lever a testnet uses to prove a positive stake-reward harvest without waiting a full week.
        let change = ParamChange::SetRewardEpochBlocks(600);
        // GOSSIP ROUND-TRIP: a peer reconstructs the SAME change from its (kind,value) wire form → byte-identical id()
        // (a gossiped proposal/vote is indistinguishable from a local one — the from_kind_value ⇄ kind_value inverse).
        let (kind, val) = change.kind_value();
        assert_eq!(
            ParamChange::from_kind_value(kind, val),
            Some(ParamChange::SetRewardEpochBlocks(600))
        );
        assert_eq!(
            ParamChange::from_kind_value(kind, val).unwrap().id(),
            change.id()
        );
        // BICAMERAL: the miner chamber alone (2/3) is NOT enough — validators must also reach 2/3.
        let id = gov.propose(change).expect("constitutional");
        gov.vote(&id, Chamber::Miners, who(1), 2000);
        gov.vote(&id, Chamber::Miners, who(2), 2000);
        assert_eq!(
            gov.try_enact(&id, &mut params, 6000, 6000),
            Some(EnactOutcome::ValidatorsShort)
        );
        gov.vote(&id, Chamber::Validators, who(1), 2000);
        gov.vote(&id, Chamber::Validators, who(2), 2000);
        assert_eq!(
            gov.try_enact(&id, &mut params, 6000, 6000),
            Some(EnactOutcome::Enacted)
        );
        assert_eq!(
            params.reward_epoch_blocks, 600,
            "reward epoch is now the governance-set 600 blocks (live)"
        );
    }

    #[test]
    fn out_of_range_change_is_rejected_fail_closed_even_when_unanimous() {
        let mut params = ChainParams::default();
        let mut gov = Governance::new();
        // propose an over-ceiling width; both chambers vote 100%. It is CONSTITUTIONAL to propose (width is the
        // community's free choice) but still fail-closes at APPLY on the ordinary param-range ceiling.
        let id = gov
            .propose(ParamChange::SetDagWidth(
                crate::params::DAG_WIDTH_CEILING + 1,
            ))
            .expect("constitutional");
        gov.vote(&id, Chamber::Miners, who(1), 1000);
        gov.vote(&id, Chamber::Validators, who(1), 1000);
        match gov.try_enact(&id, &mut params, 1000, 1000) {
            Some(EnactOutcome::Rejected(ParamError::DagWidthOutOfRange(_))) => {}
            other => panic!("expected fail-closed rejection, got {other:?}"),
        }
        // consensus is unchanged despite a unanimous but invalid vote.
        assert_eq!(params.dag_width, 32);
    }

    // ---- CONSTITUTIONAL INVARIANTS: the three un-crossable lines are impossible BY CONSTRUCTION ----

    /// Every change that would let an adversary STEAL (dilute the peg) or TRAP (pay-to-exit) people's value is
    /// refused at BOTH layers, even under a UNANIMOUS both-chamber vote: (1) the proposal layer never opens it,
    /// so it can't accumulate a single vote; and (2) the enact gate — reached only if a proposal somehow already
    /// exists (a pre-upgrade node, or a malicious peer injecting a `ProposalOpen`) — STILL refuses before any
    /// vote is weighed. This is what "adversarial governance is impossible by construction" means concretely.
    #[test]
    fn the_three_locked_lines_cannot_be_crossed_even_by_a_unanimous_vote() {
        let bad_changes = [
            ParamChange::SetMintRatioBps(MINT_RATIO_BACKING_FLOOR_BPS - 1), // just under the 110% solvency floor
            ParamChange::SetMintRatioBps(0), // a zero-collateral mint (peg dilution)
            ParamChange::SetStakeLockBlocks(0), // zero unbond delay — nothing-at-stake
            ParamChange::SetWithdrawFeeBand(0, WITHDRAW_FEE_EXCLUSION_CEILING_BPS + 1), // confiscatory pay-to-exit
        ];
        for bad in bad_changes {
            // (1) PROPOSAL LAYER — propose() refuses; the proposal never opens, so no vote can ever attach to it.
            let mut gov = Governance::new();
            assert!(
                gov.propose(bad).is_err(),
                "unconstitutional change must be refused at propose: {bad:?}"
            );
            assert!(gov.is_empty(), "a refused proposal never opens");

            // (2) ENACT LAYER (defense in depth) — hand-build the proposal (bypassing propose) and cram BOTH
            // chambers to a unanimous tally. The enact gate returns Unconstitutional BEFORE weighing votes or
            // touching params, so the live consensus is byte-for-byte unchanged. No vote count can enact it.
            let mut params = ChainParams::default();
            let untouched = params.clone();
            let mut p = Proposal::new(bad);
            p.vote(Chamber::Miners, who(1), 1_000_000);
            p.vote(Chamber::Validators, who(1), 1_000_000);
            assert!(
                matches!(
                    p.try_enact(&mut params, 1_000_000, 1_000_000),
                    EnactOutcome::Unconstitutional(_)
                ),
                "even a unanimous both-chamber vote cannot enact {bad:?}"
            );
            assert_eq!(
                params, untouched,
                "the live params are UNCHANGED — the constitutional line held"
            );
        }
    }

    /// The Monero-ethos guarantee (user 2026-07-12): governance is NOT over-restrictive. The community owns EVERY
    /// throughput / latency / economic knob — including LOWERING the DAG width and taking the mint ratio down to
    /// the floor. Those changes are constitutional (open + enact normally); only the three theft/trap lines are
    /// locked. This test would FAIL if the constitution over-reached back into the community's free choices.
    #[test]
    fn community_freely_votes_every_throughput_and_economic_knob() {
        let free_changes = [
            ParamChange::SetDagWidth(8),  // a smaller DAG — the community's call
            ParamChange::SetDagWidth(64), // a bigger DAG
            ParamChange::SetTargetSpacingMs(2000), // slower blocks
            ParamChange::SetTargetSpacingMs(250), // faster blocks
            ParamChange::SetMintRatioBps(MINT_RATIO_BACKING_FLOOR_BPS), // exactly at the 110% floor (allowed)
            ParamChange::SetMintRatioBps(12_000),                       // a safer 120% peg
            ParamChange::SetStakeLockBlocks(1),                         // the minimum positive lock
            ParamChange::SetStakeLockBlocks(10_000),                    // a long lock
            ParamChange::SetWithdrawFeeBand(0, WITHDRAW_FEE_EXCLUSION_CEILING_BPS), // exactly at the fee ceiling
            ParamChange::SetStakeRewardAprBps(500),
            ParamChange::SetRewardEpochBlocks(600),
        ];
        for ok in free_changes {
            let mut gov = Governance::new();
            assert!(
                gov.propose(ok).is_ok(),
                "the community must be free to propose {ok:?}"
            );
        }

        // ...and LOWERING the DAG width actually ENACTS end-to-end through the bicameral 2/3-of-both flow, live.
        let mut params = ChainParams::default();
        assert_eq!(params.dag_width, 32);
        let mut gov = Governance::new();
        let id = gov
            .propose(ParamChange::SetDagWidth(8))
            .expect("constitutional");
        gov.vote(&id, Chamber::Miners, who(1), 3000);
        gov.vote(&id, Chamber::Miners, who(2), 3000);
        gov.vote(&id, Chamber::Validators, who(1), 3000);
        gov.vote(&id, Chamber::Validators, who(2), 3000);
        assert_eq!(
            gov.try_enact(&id, &mut params, 9000, 9000),
            Some(EnactOutcome::Enacted)
        );
        assert_eq!(
            params.dag_width, 8,
            "the community lowered the DAG width — governance is not over-restrictive"
        );
        assert_eq!(params.ghostdag_k, 8, "k tracks the community-chosen width");
    }
}

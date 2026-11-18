// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ DB-370 — SLASHING PROTECTION: A VALIDATOR NEVER SIGNS A SECOND BLOCK AT A HEIGHT IT ALREADY VOTED, ACROSS RESTARTS.
//! (docs/DB-370-A-RESTART-MUST-NEVER-MAKE-AN-HONEST-VALIDATOR-SLASHABLE.md)
//!
//! WHAT WAS WRONG (rogue-role census, 2026-10-03). The finality voters (`serve.rs`, `main.rs` `run_node_runtime`) kept
//! their only memory of what they signed in a local `let mut last_voted: u64 = 0`. A restart reset it, and the restarted
//! voter re-voted the last `FINALITY_CATCH_UP` levels. Each level's block is picked by received vote weight
//! (`Node::finality_vote_targets`), and that tally is not persisted, so after a restart the voter picked by lowest id.
//! MEASURED (`node::tests::db370_…`): "before the restart the voter signed level 1 → 86e5fd46; after it → 6589fa92 … the
//! pair proves an equivocation by the honest voter = true". That pair is a valid `Class::Equivocation` (DB-266): any
//! node carries it, and every node burns the honest operator's bond and bars its id forever.
//!
//! THE BORROWED SHAPE is Ethereum's minimal slashing protection (EIP-3076): sign only strictly increasing heights, and put
//! the height on DISK before the signature exists (write-ahead). A crash between the write and the signature loses one
//! vote, never safety. ONE fixed 24-byte record beside the node's vote key, overwritten in place: no growth on any axis.
//! USER-APPROVED local write (2026-10-03, `~/.claude/hooks/user-approved-local-storage.txt`: `vote_guard.rs:write_durably`).
//!
//! ⛔ FAIL-CLOSED FOR THE BOND: a record that exists but does not parse, or a write that does not reach the disk, makes this
//! node REFUSE TO VOTE (said loudly). A missing vote costs finality one voice; a double vote costs the operator its bond.
//!
//! NOT CLOSED HERE (named): the SAME vote key on two machines (Ethereum's "doppelganger"). Each process keeps its own
//! record, so two processes can sign two blocks at one height. That needs doppelganger detection, filed separately.

use std::path::{Path, PathBuf};

/// The record's magic, so a foreign or truncated file is never read as a height.
const MAGIC: &[u8; 8] = b"MUSDVG01";
/// magic ‖ last voted height (LE) ‖ blake3(magic ‖ height)[..8].
const RECORD_BYTES: usize = 24;

/// The write-ahead record of the highest height this node's vote key has signed (or is about to sign).
#[derive(Debug)]
pub struct VoteGuard {
    path: PathBuf,
    last: u64,
    /// The record exists and does not parse (or cannot be read): every vote is refused.
    locked: bool,
    /// ⭐ §BR-9a — when this voter last tried to publish a deal for each epoch the pool did not take (the peg lane's own
    /// publish backoff, `PEG_PUBLISH_BACKOFF_MS`, before the next try). Process-local: a restart simply tries again.
    /// O1-INFINITY-REVIEWED: at most the epochs now dealing (≤ DEAL_LEAD_EPOCHS), pruned to them on every tick.
    deal_tried_ms: std::collections::BTreeMap<u64, u64>,
    /// ⭐ SPEED L2 (docs/CHAIN-SPEED-SPEC-20261109.md §6.2) — when this voter first held a tip at each recent blue score:
    /// `(blue score, this node's clock ms)`, ascending. Process-local: after a restart the voter waits the constant
    /// depth until the ring refills. O1-INFINITY-REVIEWED: at most FINALITY_SETTLE + 2 rows, a fixed constant at any height.
    level_seen: std::collections::VecDeque<(u64, u64)>,
}

fn checksum(height: u64) -> [u8; 8] {
    let mut h = blake3::Hasher::new();
    h.update(MAGIC);
    h.update(&height.to_le_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize().as_bytes()[..8]);
    out
}

impl VoteGuard {
    /// The guard beside this node's vote key (`validator-<port>.key` → `validator-<port>.vote-guard`).
    #[must_use]
    pub fn for_node_vote_key() -> VoteGuard {
        VoteGuard::open(crate::validator::node_vote_key_path().with_extension("vote-guard"))
    }

    /// Open the guard at `path`. A missing record is a key that never voted (height 0). A record that exists and does not
    /// parse, or cannot be read, locks the guard: the node refuses to vote rather than guess what it signed.
    #[must_use]
    pub fn open(path: PathBuf) -> VoteGuard {
        match std::fs::read(&path) {
            Ok(b) => match Self::parse(&b) {
                Some(last) => VoteGuard { path, last, locked: false, deal_tried_ms: std::collections::BTreeMap::new(), level_seen: std::collections::VecDeque::new() },
                None => {
                    eprintln!(
                        "[vote-guard] ⛔ DB-370: the slashing-protection record exists and does not parse — this node \
                         REFUSES TO VOTE (a double vote would burn its bond). Inspect the record beside the vote key."
                    );
                    VoteGuard { path, last: u64::MAX, locked: true, deal_tried_ms: std::collections::BTreeMap::new(), level_seen: std::collections::VecDeque::new() }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => VoteGuard { path, last: 0, locked: false, deal_tried_ms: std::collections::BTreeMap::new(), level_seen: std::collections::VecDeque::new() },
            Err(e) => {
                eprintln!("[vote-guard] ⛔ DB-370: the slashing-protection record cannot be read ({e}) — this node REFUSES TO VOTE.");
                VoteGuard { path, last: u64::MAX, locked: true, deal_tried_ms: std::collections::BTreeMap::new(), level_seen: std::collections::VecDeque::new() }
            }
        }
    }

    fn parse(b: &[u8]) -> Option<u64> {
        if b.len() != RECORD_BYTES || &b[..8] != MAGIC {
            return None;
        }
        let height = u64::from_le_bytes(b[8..16].try_into().ok()?);
        (b[16..24] == checksum(height)).then_some(height)
    }

    /// The highest height this key has signed or reserved. Every vote at or below it is refused.
    #[must_use]
    pub fn last_voted(&self) -> u64 {
        self.last
    }

    /// Whether the guard refuses every vote (an unreadable record).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// ⭐ SPEED L2 — this voter's tip stands at blue score `tip_blue` at `now_ms` (its own clock). The first sighting of each
    /// score is kept; a tip that fell (a reorg to a lower score) forgets the scores above it.
    pub fn note_tip(&mut self, tip_blue: u64, now_ms: u64) {
        while self.level_seen.back().is_some_and(|(b, _)| *b > tip_blue) {
            self.level_seen.pop_back();
        }
        if self.level_seen.back().map_or(true, |(b, _)| *b < tip_blue) {
            self.level_seen.push_back((tip_blue, now_ms));
        }
        while self.level_seen.len() > (FINALITY_SETTLE + 2) as usize {
            self.level_seen.pop_front();
        }
    }

    /// ⭐ SPEED L2 + R2 (docs/CHAIN-SPEED-SPEC-20261109.md §6.2, docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §3) — how far below
    /// its tip this voter votes NOW: the least depth `s` in `SETTLE_MIN..FINALITY_SETTLE` whose level `tip − s` has had a
    /// block AT OR ABOVE it in this voter's hands for two of its own longest measured relay rounds; else
    /// [`FINALITY_SETTLE`], today's depth. Never deeper than today, and with no level minimum: the wait is a time only.
    /// ROOT-LAYER: the one depth `vote_tick` hands `targets_above`. The voter's OWN policy: what makes a vote valid, one
    ///   vote per level, the write-ahead record and slashing are untouched, so every node accepts exactly the votes it
    ///   accepts today (bus verdict 2026-11-09: a split level is skipped and a later agreed level finalizes its past, so
    ///   the risk is liveness, never safety).
    /// MEASURED: rig -s 2026-11-09 — block birth to final 122 s median, 82 s of it the 8 levels at 10.2 s a level. The 8 is
    ///   "every block at the level has propagated" (runs 66–70) written as a block count: 82 s here, 4.8 s at the target.
    /// BORROWED: a timer that follows the measured network (RFC 6298); the finality rule itself is unchanged.
    /// The LONGEST of the voter's measured rounds is used, so one fast moment never lets it vote early. With no measure
    /// (a fresh process, a pair that never pulled by id) the depth is the constant.
    /// cons: 0 B. A voter whose measure is too small votes early and its vote can miss that level's quorum, as today.
    /// MUST-STAY-GREEN: the vote_guard pins (db370), `a_finality_vote_cannot_finalize…`, and on real nodes the share of
    ///   levels where every validator names the same block (≥ 95 %) with finality never stalling across a partition and heal.
    #[must_use]
    pub fn settle_levels(&self, tip_blue: u64, now_ms: u64, relay_round_max_ms: Option<u64>) -> u64 {
        // CHAIN-OBJECT: the finality vote this depth leads to (`Class::FinalityVote`, carried by a block and tallied at the
        // fold) is the only thing that moves finality; the depth is when THIS voter signs, and no node reads another's.
        self.settle_levels_by_round(tip_blue, now_ms, relay_round_max_ms)
    }

    /// The rule itself, a pure function of this voter's level clock and its measured round (pinned directly).
    /// CHAIN-OBJECT: as [`Self::settle_levels`] — the carried vote is the transition; this only times the signature.
    #[must_use]
    pub fn settle_levels_by_round(&self, tip_blue: u64, now_ms: u64, relay_round_max_ms: Option<u64>) -> u64 {
        self.settle_levels_by_need(tip_blue, now_ms, relay_round_max_ms.map(|r| r.saturating_mul(2)))
    }

    /// ⭐ SPEED stage 2 (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11.10) — HOW LONG A LEVEL MUST HAVE BEEN HELD BEFORE THIS
    /// VOTER SIGNS IT, from what the wait is for. A sibling of the voter's block at that level is a block whose producer
    /// did not yet HOLD the voter's block when it finished its own. Parents are named when a proof finishes
    /// (`rebind_parents_at_proof_finish`), so that producer finishes within one whole-block fetch of the voter's block
    /// being published, and its block is ANNOUNCED one small round trip later. So:
    /// * no measure of whole-block fetches: `None` (the caller keeps the constant depth);
    /// * no measure of small round trips, or a block this node was told about has not arrived
    ///   (`fetch_outstanding`: it may be that sibling): two whole-block fetches, the rule as it was;
    /// * otherwise: one whole-block fetch plus one small round trip. After that every sibling has been announced, and an
    ///   announced one is a fetch outstanding, which is the case above.
    /// The longest measured value of each is used. Never longer than the rule it replaces (a small round trip longer
    /// than a whole-block fetch is read as a whole-block fetch).
    /// Voter policy: what makes a vote valid, one vote per level, the write-ahead record and slashing are untouched. The
    /// risk is the one R2 already carries — a level whose votes split is skipped and the next agreed level finalizes
    /// its past — and it is liveness only.
    /// MODEL (`scratchpad/speed/settle_model.py`, checked against two real runs to 5 %): with the votes laid at the seal,
    /// this takes the wait from 2 × 6.6 s to about 8.3 s on the measured pair.
    /// CHAIN-OBJECT: the carried finality vote is the transition; this only times the signature.
    #[must_use]
    pub fn settle_need_ms(relay_round_max_ms: Option<u64>, small_round_max_ms: Option<u64>, fetch_outstanding: bool) -> Option<u64> {
        let round = relay_round_max_ms?;
        match small_round_max_ms {
            Some(small) if !fetch_outstanding => Some(round.saturating_add(small.min(round))),
            _ => Some(round.saturating_mul(2)),
        }
    }

    /// [`Self::settle_levels_by_round`] for a wait given directly (`None`: the constant depth).
    /// CHAIN-OBJECT: as [`Self::settle_levels`] — the carried vote is the transition; this only times the signature.
    #[must_use]
    pub fn settle_levels_by_need(&self, tip_blue: u64, now_ms: u64, need_ms: Option<u64>) -> u64 {
        let Some(need) = need_ms else { return FINALITY_SETTLE };
        for s in SETTLE_MIN..FINALITY_SETTLE {
            let level = tip_blue.saturating_sub(s);
            // R2: the first time this voter's tip stood AT OR ABOVE `level` — a block at that level has been in its hands
            // since then, so a sibling made at the same moment has had that long to arrive. A ring that does not reach
            // back that far names a LATER time, which only makes the voter wait longer.
            let held_since = self.level_seen.iter().find(|(b, _)| *b >= level).map(|(_, at)| *at);
            if held_since.is_some_and(|at| now_ms.saturating_sub(at) >= need) {
                return s;
            }
        }
        FINALITY_SETTLE
    }

    /// ⛔ WRITE-AHEAD: reserve `height` BEFORE a signature at it exists. `true` only when `height` is strictly above every
    /// height this key has reserved AND the record reached the disk. On `false` the caller must not sign.
    pub fn reserve(&mut self, height: u64) -> bool {
        if self.locked || height == 0 || height <= self.last {
            return false;
        }
        match Self::write_durably(&self.path, height) {
            Ok(()) => {
                self.last = height;
                true
            }
            Err(e) => {
                eprintln!("[vote-guard] ⛔ DB-370: the slashing-protection record could not be written ({e}) — not signing.");
                false
            }
        }
    }

    /// The record to a sibling, synced, atomically renamed over the old one, and the directory entry synced: a crash at
    /// any point leaves either the old record or the new one, never a torn one.
    fn write_durably(path: &Path, height: u64) -> std::io::Result<()> {
        use std::io::Write;
        let mut rec = Vec::with_capacity(RECORD_BYTES);
        rec.extend_from_slice(MAGIC);
        rec.extend_from_slice(&height.to_le_bytes());
        rec.extend_from_slice(&checksum(height));
        let tmp = path.with_extension("vote-guard.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&rec)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// The levels a voter may sign this tick: `Node::finality_vote_targets` ABOVE the guard's record (never the voter's own
/// memory, which a restart erases), each strictly above it. The serve voter calls exactly this, and the caller then
/// RESERVES each height (`VoteGuard::reserve`, write-ahead) before it signs it, outside the runtime lock (one fsync per
/// level; normally one level per tick).
#[must_use]
pub fn targets_above(node: &crate::node::Node, guard: &VoteGuard, settle: u64, catch_up: u64) -> Vec<(crate::block::BlockId, u64)> {
    targets_above_for(node, guard, None, settle, catch_up)
}

/// ⭐ A-F86 — [`targets_above`] for the key `voter`: its levels extend the chain its own open votes stand on
/// (`Node::finality_vote_targets_for`), so one voter never votes two chains.
#[must_use]
pub fn targets_above_for(
    node: &crate::node::Node,
    guard: &VoteGuard,
    voter: Option<[u8; 32]>,
    settle: u64,
    catch_up: u64,
) -> Vec<(crate::block::BlockId, u64)> {
    let floor = guard.last_voted();
    if guard.is_locked() {
        return Vec::new();
    }
    node.finality_vote_targets_for(voter, floor, settle, catch_up).into_iter().filter(|(_, h)| *h > floor).collect()
}

/// ⭐ DB-437 — the depth a level is voted at and how many levels one tick catches up, for EVERY voter. A level is voted
/// once it is one DAG width deep, when every block at it has propagated and every validator sees the same set (MEASURED
/// runs 66–70, 2026-09-18, two real producers over Tor: voted four levels behind the tip, the validators named different
/// blocks at most levels and finality stopped at 110/74 in every run). The daemon's voter (`main.rs`) still ran the
/// superseded rule (stride 4, settle 2, the selected-chain block — the shape runs 39/40 measured freezing at [1, 0]); it
/// now calls [`vote_tick`] like the in-process node and the simulator.
/// MEASURED 2026-11-04, two real producers with their chains crossing: at 8, 0 rewinds through tip 312 and finality 15 levels behind the tip (at 32: about 36).
pub const FINALITY_SETTLE: u64 = 8;
pub const FINALITY_CATCH_UP: u64 = 16;
/// SPEED L2 / R2 (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §3) — the least depth a voter votes at: 0, its own tip's level.
/// It was 2 (the level's block and one above it in the tip's past), which was the last BLOCK COUNT in the vote path: on a
/// mesh whose blocks are a proof-time apart that is two proofs of waiting for nothing the wait is for. What the wait is
/// for — a sibling made at the same moment reaching this voter — is a TIME, and `settle_levels_by_round` already waits it.
pub const SETTLE_MIN: u64 = 0;

/// ONE voter tick, shared by the daemon, the in-process node and the simulator: the levels this key may sign
/// ([`targets_above`] under the runtime lock), each height RESERVED write-ahead and signed OUTSIDE the lock, then each
/// cert submitted (counted locally + gossiped) under the lock. A refused reservation stops the tick (nothing at or above
/// it is signed); a level whose signature fails is skipped, as both voters did. Returns each cast level and its outcome.
/// ROOT-LAYER: the vote is produced here for every voter — before, two loops produced it by two rules and the simulator
///   had none.
/// MEASURED: link 43, night/perf-flat-20261008-154831-high.log — P4 `finalized 0` at tip 3,171 and at 20,333, every node
///   `serving 0 certificate(s)` (nothing ever voted in the simulator).
/// MUST-STAY-GREEN: the vote_guard pins (db370), the finality pins in node.rs (`a_finality_vote_cannot_finalize…`), the fast
///   journey.
/// cons: none — the in-process voter's own steps, moved here; the daemon's voter now waits the measured 32-level depth.
pub fn vote_tick<T: crate::transport::CellTransport>(
    rt: &std::sync::Mutex<crate::node_runtime::NodeRuntime<T>>,
    guard: &mut VoteGuard,
    pk: &[u8],
    sk: &[u8],
) -> Vec<(u64, crate::validator::FinalityVoteOutcome)> {
    #[cfg(test)]
    let mut tip_trace = String::new();
    let targets = {
        let r = rt.lock().unwrap_or_else(|e| e.into_inner());
        #[cfg(test)]
        if let Some(t) = r.node().selected_tip() {
            let mut tips: Vec<String> = r.node().dag().tips().iter().map(|x| format!("{}:{}", &x.to_hex()[..6], r.node().dag().get(x).map_or(0, |n| n.blue_score))).collect();
            tips.sort();
            tip_trace = format!("tip {}:{} of {tips:?}", &t.to_hex()[..6], r.node().dag().get(&t).map_or(0, |n| n.blue_score));
        }
        // SPEED L2: the depth follows this voter's own measured relay round (`VoteGuard::settle_levels`), never past today's.
        // CHAIN-OBJECT: the finality vote this depth leads to (`Class::FinalityVote`, carried by a block and tallied at the
        // fold) is the only thing that moves finality. The depth decides WHEN this voter signs, exactly as the constant did
        // against this node's own tip; no node reads another node's depth, and no two nodes need to agree on it.
        let settle = match r.node().selected_tip().and_then(|t| r.node().dag().get(&t).map(|n| n.blue_score)) {
            Some(tip_blue) => {
                let now_ms = r.now_unix_ms();
                guard.note_tip(tip_blue, now_ms);
                // SPEED stage 2: the wait is one whole-block fetch plus one small round trip while nothing this node was
                // told about is still on its way; two whole-block fetches otherwise (`VoteGuard::settle_need_ms`).
                // CHAIN-OBJECT: the carried finality vote is the transition; this only times this voter's signature.
                // ⭐ V3 (spec LEVEL-AGGREGATE §15.2, speed5 2026-11-16) — WITH NO MEASURE, THE DERIVED TIME, NEVER A BLOCK COUNT.
                // A voter with fewer than RELAY_ROUND_MIN measured pulls by id (a fresh process; a producer whose peers'
                // blocks reach it by relay parts) had no measure and fell to FINALITY_SETTLE: 8 LEVELS, a block count whose
                // time is 8 × the level interval. MEASURED on real nodes (rig ~/.usdmd-net-af58, main 5b6d9720, 2 nodes,
                // 11:25): node 0 holds no relay-round record, node 1 two samples (< 4); every height was seen final 73-78 s
                // after its block's timestamp, all of it timestamp → first vote, quorum 0 ms after.
                // The wait is for a sibling to arrive, and that is a TIME: two relay rounds of one block, the one derived
                // constant the producer's spacing and the fold depth already use (`dag::FOLD_SETTLE_MS`, ≈ 9.3 s at the
                // reference rate). A measure, once it exists, replaces it, longer or shorter, as before.
                // Voter policy only: what makes a vote valid, one vote per level, the write-ahead record and slashing are
                // untouched; a level whose votes split is skipped and the next agreed level finalizes its past (liveness, as
                // with any short measure). AI RESISTANT: (b) a timer; the finality rule it feeds is a 2/3 bonded quorum.
                // SCALE: a constant. cons: 0 B; on a link slower than the reference a fresh voter may sign before a sibling
                // arrives while it has under RELAY_ROUND_MIN rounds measured, costing that level, never safety.
                let need = VoteGuard::settle_need_ms(
                    r.relay_round_max_ms(),
                    crate::node_runtime::small_round_max_ms(),
                    r.block_fetch_outstanding(now_ms),
                )
                .or(Some(crate::dag::FOLD_SETTLE_MS));
                guard.settle_levels_by_need(tip_blue, now_ms, need)
            }
            None => FINALITY_SETTLE,
        };
        targets_above_for(r.node(), guard, Some(crate::pqauth::pubkey_id(pk)), settle, FINALITY_CATCH_UP)
    };
    let mut cast = Vec::new();
    #[cfg(test)]
    if std::env::var("REPLAY_TX_TRACE").is_ok_and(|v| v == "all") {
        let t: Vec<(String, u64)> = targets.iter().map(|(b, h)| (b.to_hex()[..8].to_string(), *h)).collect();
        eprintln!("[tx-trace] voter t 0 vote-targets pk{:02x}{:02x} above {} {t:?} {tip_trace} 00000000 link None · []", pk[0], pk[1], guard.last_voted());
    }
    for (block, height) in targets {
        // The height reaches the disk BEFORE a signature at it exists; a refused reservation signs nothing.
        if !guard.reserve(height) {
            break;
        }
        let sig = match crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&block, height), sk) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let outcome = {
            let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
            r.submit_finality_vote(crate::validator::VoteCert { pubkey: pk.to_vec(), block, height, sig })
        };
        #[cfg(test)]
        crate::budget_clock::replay_tx_trace(&format!("vote-cast h{height} pk{:02x}{:02x} {outcome:?}", pk[0], pk[1]), &block.0, None);
        if crate::validator::finality_trace_enabled() {
            eprintln!("[finality-vote] cast h={height} block={} outcome={outcome:?}", &block.to_hex()[..8]);
        }
        cast.push((height, outcome));
    }
    // ⭐ §BR-10: beside its votes, the validator signals every Started deployment its release implements (once per window)
    let due = {
        let r = rt.lock().unwrap_or_else(|e| e.into_inner());
        r.node().deployment_signal_due(&crate::pqauth::pubkey_id(pk))
    };
    for (bits, window) in due {
        let vid = crate::pqauth::pubkey_id(pk);
        if let Some(sig) = crate::pqauth::ml_dsa_sign(&crate::deployment_signal_tx::signal_msg(&vid, bits, window), sk) {
            let t = crate::deployment_signal_tx::DeploymentSignalTx { vid, bits, window, pubkey: pk.to_vec(), sig };
            let mut r = rt.lock().unwrap_or_else(|e| e.into_inner());
            let _ = r.node_mut().publish_deployment_signal(&t);
        }
    }
    // ⭐ §BR-9a: a custodian deals for the epoch now dealing, once — fresh seed and Shamir coefficients from OS entropy,
    // shares sealed to the roster's custody keys; the key sum and every member's share capture are the fold's.
    let (deal_due, now_ms) = match rt.lock() {
        Ok(r) => (r.node().epoch_key_deal_due(&crate::pqauth::pubkey_id(pk)), r.now_unix_ms()),
        Err(poisoned) => {
            let r = poisoned.into_inner();
            (r.node().epoch_key_deal_due(&crate::pqauth::pubkey_id(pk)), r.now_unix_ms())
        }
    };
    let due_epochs: std::collections::BTreeSet<u64> = deal_due.iter().map(|(e, _)| *e).collect();
    guard.deal_tried_ms.retain(|e, _| due_epochs.contains(e));
    for (epoch, roster) in deal_due {
        // a deal the pool did not take is tried again after the peg lane's publish backoff, never every 200 ms tick
        if guard.deal_tried_ms.get(&epoch).is_some_and(|t| now_ms.saturating_sub(*t) < crate::peg_attest::PEG_PUBLISH_BACKOFF_MS) {
            continue;
        }
        guard.deal_tried_ms.insert(epoch, now_ms.max(1));
        let t = crate::shamir::two_thirds_threshold(roster.len());
        let seed = crate::cashout_ticket::fresh_entropy(32).and_then(|s| <[u8; 32]>::try_from(s.as_slice()).ok());
        let coeffs = crate::cashout_ticket::fresh_entropy(t.saturating_sub(1) * 32);
        if let (Some(seed), Some(coeffs)) = (seed, coeffs) {
            if let Some(deal) = crate::epoch_deal_tx::build(pk, sk, epoch, &roster, &seed, &coeffs) {
                let _ = match rt.lock() {
                    Ok(mut r) => r.node_mut().publish_epoch_key_deal(&deal),
                    Err(poisoned) => poisoned.into_inner().node_mut().publish_epoch_key_deal(&deal),
                };
            }
        }
    }
    cast
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::VoteGuard;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("usdmd-vote-guard-{}-{tag}", std::process::id()))
    }

    /// The record survives a restart (a fresh open), refuses every height at or below it, and a corrupt record LOCKS the
    /// guard rather than reading as height 0 (which would re-open every past level to a second signature).
    /// TWO-PARTY-REVIEWED: the record is ONE signer's own memory of what it signed (a single-party local fact by
    /// definition). The second party — every node that would verify the evidence and slash — is exercised by
    /// `node::tests::db370_a_restarted_voter_never_signs_a_second_block_at_a_level_it_already_voted`.
    #[test]
    fn the_guard_survives_a_restart_refuses_a_repeat_height_and_locks_on_a_corrupt_record() {
        let p = tmp("basic");
        let _ = std::fs::remove_file(&p);
        let mut g = VoteGuard::open(p.clone());
        assert_eq!(g.last_voted(), 0, "a key that never voted");
        assert!(g.reserve(5), "a fresh height reserves");
        assert!(!g.reserve(5) && !g.reserve(4), "a height at or below the record is refused");
        let mut again = VoteGuard::open(p.clone());
        assert_eq!(again.last_voted(), 5, "⛔ the record did not survive a restart");
        assert!(!again.reserve(5), "⛔ a restarted guard re-reserved a height it already signed");
        assert!(again.reserve(9), "a higher height reserves after the restart");
        std::fs::write(&p, b"garbage").expect("write");
        let mut locked = VoteGuard::open(p.clone());
        assert!(locked.is_locked(), "⛔ a corrupt record must lock the guard, never read as height 0");
        assert!(!locked.reserve(u64::MAX - 1), "a locked guard reserves nothing");
        let _ = std::fs::remove_file(&p);
    }

    /// ⭐ SPEED L2 — the depth a voter votes at follows its own measured relay round and stays within `SETTLE_MIN` and the
    /// constant whatever it is fed: no measure, a tip it has only just seen, a measure of one millisecond (a peer that
    /// answered instantly), a measure of an hour (a peer that stalled), a clock that ran backwards, and a tip that
    /// dropped to a lower score in a reorg.
    /// TWO-PARTY-REVIEWED: the depth is ONE voter's own choice of when to sign (a single-party local fact by definition).
    /// The second party — every node that tallies the vote — reads no depth: it accepts exactly the votes it accepted
    /// before, which the finality pins in node.rs and the real-node screen (two validators naming one block per level)
    /// exercise.
    #[test]
    fn the_settle_wait_is_one_block_fetch_and_one_small_round_unless_a_told_block_has_not_arrived() {
        // no measure of whole-block fetches: no wait is derived (the caller keeps the constant depth)
        assert_eq!(VoteGuard::settle_need_ms(None, Some(1_500), false), None);
        // no measure of small round trips: two whole-block fetches, the rule as it was
        assert_eq!(VoteGuard::settle_need_ms(Some(6_000), None, false), Some(12_000));
        // a block this node was told about is still on its way: it may be the sibling, so the long wait stands
        assert_eq!(VoteGuard::settle_need_ms(Some(6_000), Some(1_500), true), Some(12_000), "⛔ the voter shortened its wait with a told block outstanding");
        // nothing outstanding: one whole-block fetch plus one small round trip
        assert_eq!(VoteGuard::settle_need_ms(Some(6_000), Some(1_500), false), Some(7_500));
        // never longer than the rule it replaces: a small round trip slower than a block fetch counts as a block fetch
        assert_eq!(VoteGuard::settle_need_ms(Some(6_000), Some(9_000), false), Some(12_000));
        // and the depth follows the wait: a level held 8 s is voted at depth 0 under 7.5 s, and not under 12 s
        let mut g = VoteGuard::open(std::env::temp_dir().join(format!("musd-vote-guard-need-{}", std::process::id())));
        g.note_tip(100, 10_000);
        assert_eq!(g.settle_levels_by_need(100, 18_000, Some(7_500)), 0);
        assert_ne!(g.settle_levels_by_need(100, 18_000, Some(12_000)), 0, "⛔ a level held 8 s was voted under a 12 s wait");
        // CHAIN-OBJECT: the carried finality vote is the transition; this depth only times a voter's signature (a test of it).
        assert_eq!(g.settle_levels_by_need(100, 18_000, None), crate::vote_guard::FINALITY_SETTLE);
    }

    #[test]
    fn the_settle_depth_follows_the_measured_round_and_stays_within_zero_to_eight_levels() {
        use super::{FINALITY_SETTLE, SETTLE_MIN};
        let p = tmp("settle");
        let _ = std::fs::remove_file(&p);
        let mut g = VoteGuard::open(p.clone());
        // no measure: the constant depth, whatever the clock says
        g.note_tip(100, 1_000);
        assert_eq!(g.settle_levels_by_round(100, 999_999, None), FINALITY_SETTLE, "⛔ a voter with no measured round left the constant depth");
        // a 4 s round: the voter has held a block at level 100 for 0 ms, so no depth under the constant is settled yet
        assert_eq!(g.settle_levels_by_round(100, 1_000, Some(4_000)), FINALITY_SETTLE, "⛔ a level voted the instant its block arrived");
        assert_eq!(g.settle_levels_by_round(100, 8_999, Some(4_000)), FINALITY_SETTLE, "⛔ a level voted before two rounds passed");
        // two rounds later the tip's own level is settled (R2: the wait is a time, with no level minimum)
        assert_eq!(g.settle_levels_by_round(100, 9_000, Some(4_000)), SETTLE_MIN, "⛔ two rounds passed and the voter still waits the constant depth");
        // a hostile measure of 1 ms (a peer that answers instantly) votes the tip's level after 2 ms and never above the tip
        assert_eq!(g.settle_levels_by_round(100, 1_001, Some(1)), FINALITY_SETTLE, "⛔ a level voted before even a tiny measure's two rounds");
        assert_eq!(g.settle_levels_by_round(100, 1_002, Some(1)), SETTLE_MIN, "⛔ a tiny round voted somewhere other than the tip's level");
        // a hostile measure of an hour (a peer that stalls) never takes the voter deeper than the constant
        assert_eq!(g.settle_levels_by_round(100, 60_000, Some(3_600_000)), FINALITY_SETTLE, "⛔ a huge round pushed the depth past today's");
        // a clock that ran backwards settles nothing early
        assert_eq!(g.settle_levels_by_round(100, 500, Some(4_000)), FINALITY_SETTLE, "⛔ a clock behind the sighting counted as time passed");
        // the tip climbs a level every 3 s: with an 8 s wait (2 × 4 s) the settled level is the one whose upper neighbour is 8 s old
        for (i, t) in (101u64..=106).zip((4_000u64..).step_by(3_000)) {
            g.note_tip(i, t);
        }
        // at t = 19,000 the tip is 106 (seen 19,000); 105 seen 16,000; 104 at 13,000; 103 at 10,000 → level 103 held for 9 s
        // CHAIN-OBJECT: (a test of the voter's own timing) the carried finality vote is the transition; this reads no state.
        assert_eq!(g.settle_levels_by_round(106, 19_000, Some(4_000)), 3, "⛔ the depth is not the first level held two rounds");
        // a reorg to a lower tip forgets the scores above it and keeps the sightings at and below it
        g.note_tip(101, 20_000);
        assert_eq!(g.settle_levels_by_round(101, 20_000, Some(4_000)), SETTLE_MIN, "⛔ a lower tip lost the sightings at and below it");
        // 102 was first seen at 7,000, left in the reorg, and is reached again at 21,000; the tip then moves to 103. Level 102
        // has been held only since 21,000 (1 s), so depth 1 is not settled and depth 2 (level 101, held since 4,000) is.
        // Had the old sighting of 102 survived the reorg, the voter would sign level 102 after one second.
        // CHAIN-OBJECT: (a test of the voter's own timing) the carried finality vote is the transition; this reads no state.
        g.note_tip(102, 21_000);
        g.note_tip(103, 22_000);
        assert_eq!(g.settle_levels_by_round(103, 22_000, Some(4_000)), 2, "⛔ a score reached again after a reorg kept its OLD sighting");
        let _ = std::fs::remove_file(&p);
    }
}

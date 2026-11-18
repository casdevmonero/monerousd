// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-9a step (b) — A CUSTODIAN'S EPOCH-KEY DEAL (`Class::EpochKeyDeal`) and the EPOCH-KEY LEDGER the fold keeps
//! (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §19, §19.1, §19.2).
//!
//! Every hour is one epoch. While the fold is in epoch c, each bonded custodian deals for epoch c + [`DEAL_LEAD_EPOCHS`]:
//! it publishes its public part b_i = A·s_i + e_i (`epoch_key::deal`, from a fresh 32-byte seed) and, for every member of
//! that epoch's roster, one Shamir share of its seed (GF(2⁸), t = ⌈2n/3⌉) sealed to the member's ML-KEM-768 custody key, with
//! a commitment to the plaintext share the dealer signs. The fold sums the public parts into the epoch's ONE public key;
//! a custodian's node captures the share sealed to it at the instant the deal applies (`Node::capture_epoch_share`). The
//! key is final once its dealing hour has passed, 25 hours before its epoch, so every ticket (≤ 24 h ahead) finds a final key.
//!
//! Borrowed shapes: the GJKR distributed key generation (each dealer publishes its public part and shares its secret to
//! every member); Ethereum's signed validator messages processed at block processing; the Zcash nullifier set for "one deal
//! per custodian per epoch". The lattice instance and the seed sharing are ours (novel crypto, `epoch_key.rs`).
//!
//! §9.6 NEW DOOR: (1) PoW — the carrying block's; (2) the object's own proof — the ML-DSA-65 signature by the key whose id is
//! `vid`, over every field, at admission and at the fold; (3) value — none: it moves no note and no weight; (4) replay —
//! `deal_nf(vid, epoch)` on the lane, and the ledger refuses a second deal by the same dealer for the same epoch; (5) bounded
//! work — one signature and one sum of 1,536 coefficients; at most [`crate::peg_attest::PEG_ATTEST_SEALED_MAX`] shares;
//! (6) parity with `Class::DeploymentSignal` (the other signed validator message): the key is the vid's and the signer must
//! hold a custody seat — here, sit on the epoch's roster, snapshotted when its dealing hour opened.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: a deal carries a lattice public part, sealed shares of constant width and hash
//! commitments; it names no note, amount or user. The roster is the public custody set.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One epoch: an hour of CHAIN TIME (`Node::chain_time_ms_at`, median-time-past), at whatever rate the mesh makes blocks. It
/// was 7,200 blocks, "an hour of 500 ms blocks"; the chain has never run at that target (MEASURED 2026-11-08, real nodes:
/// about 5 blocks a minute), so an epoch was a day and a cash-out's batch two days away.
pub const EPOCH_MS: u64 = 3_600_000;
/// A custodian deals for the epoch this many epochs ahead of the fold's; the key is final one epoch later (25 h ahead), so
/// a ticket's `pay_after` (≤ 24 h, `peg::PAY_AFTER_MAX_MS`) always falls in an epoch whose key is final.
pub const DEAL_LEAD_EPOCHS: u64 = 26;
/// One plaintext share: its x-coordinate and 32 seed bytes.
pub const SHARE_BYTES: usize = 33;
const TAG_BYTES: usize = 16;

#[cfg(test)]
thread_local! {
    /// Test seam (as `DeploymentLedger::test_table`): a pin's epoch length in chain-time ms, so a two-node pin crosses epochs
    /// in a few blocks. Production always reads [`EPOCH_MS`].
    pub static TEST_EPOCH_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test seam in the unit every pin was written in: an epoch of `blocks` blocks at the chain's default spacing. The epoch clock
/// moved from blue scores to chain-time ms on 2026-11-08 and the pins' lengths (1, 4, 16 "blocks") were left as ms, so a 4 ms
/// epoch crossed about 125 epochs per 500 ms block (MEASURED: `br9a_c` read epoch 250 where the batch ending 127 was due).
#[cfg(test)]
pub fn set_test_epoch_blocks(blocks: u64) {
    TEST_EPOCH_MS.with(|c| c.set(Some(blocks * crate::params::ChainParams::default().target_spacing_ms)));
}

#[cfg(test)]
thread_local! {
    /// Test seam, beside [`TEST_EPOCH_MS`]: a pin's deal lead, so a two-node pin reaches the erasure of an epoch it dealt
    /// inside its fixture's fold-ahead cap. Production always reads [`DEAL_LEAD_EPOCHS`].
    pub static TEST_DEAL_LEAD: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// How many epochs ahead a custodian deals: [`DEAL_LEAD_EPOCHS`] (a test may shorten it on its own thread).
#[must_use]
pub fn deal_lead() -> u64 {
    #[cfg(test)]
    if let Some(n) = TEST_DEAL_LEAD.with(std::cell::Cell::get) {
        return n;
    }
    DEAL_LEAD_EPOCHS
}

/// The epoch length in chain-time ms: [`EPOCH_MS`] (a test may shorten it on its own thread).
#[must_use]
pub fn epoch_ms() -> u64 {
    #[cfg(test)]
    if let Some(n) = TEST_EPOCH_MS.with(std::cell::Cell::get) {
        return n.max(1);
    }
    EPOCH_MS
}

/// The epoch a chain time (unix ms, `Node::chain_time_ms_at`) falls in.
#[must_use]
pub fn epoch_of(chain_ms: u64) -> u64 {
    chain_ms / epoch_ms()
}

/// The public seed every epoch's matrix A is expanded from: a constant of the protocol, the same on every node.
#[must_use]
pub fn matrix_seed(epoch: u64) -> [u8; 32] {
    crate::epoch_key::epoch_seed(blake3::hash(b"MUSD/epoch-key/matrix/v1").as_bytes(), epoch)
}

/// A sealed share's width: ML-KEM ciphertext ‖ tag ‖ masked share.
#[must_use]
pub fn sealed_len() -> usize {
    crate::pqkem::ciphertext_len() + TAG_BYTES + SHARE_BYTES
}

/// One recipient's sealed share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedShare {
    pub to: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — exactly [`sealed_len`] bytes (decode refuses any other width).
    pub sealed: Vec<u8>,
    /// The dealer's commitment to the plaintext share (the fraud proof opens against it).
    pub commit: [u8; 32],
}

/// The deal, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyDealTx {
    pub vid: [u8; 32],
    pub epoch: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — exactly [`crate::epoch_key::B_BYTES`] bytes.
    pub b: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per roster member, at most `PEG_ATTEST_SEALED_MAX`.
    pub shares: Vec<SealedShare>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 public key (decode refuses any other width).
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 signature (decode refuses any other width).
    pub sig: Vec<u8>,
}

/// What the dealer's key signs: every field but the signature.
#[must_use]
pub fn deal_msg(vid: &[u8; 32], epoch: u64, b: &[u8], shares: &[SealedShare]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(&crate::pqauth::node_statement(b"MUSD/epoch-deal/msg/v1"));
    h.update(vid);
    h.update(&epoch.to_le_bytes());
    h.update(blake3::hash(b).as_bytes());
    for s in shares {
        h.update(&s.to);
        h.update(blake3::hash(&s.sealed).as_bytes());
        h.update(&s.commit);
    }
    h.finalize().as_bytes().to_vec()
}

/// One deal per custodian per epoch.
#[must_use]
pub fn deal_nf(vid: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut pre = b"MONEROUSD-EPOCH-DEAL-NF-v1".to_vec();
    pre.extend_from_slice(vid);
    pre.extend_from_slice(&epoch.to_le_bytes());
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// The commitment a dealer signs to the plaintext share it sealed to `to`.
#[must_use]
pub fn share_commit(vid: &[u8; 32], epoch: u64, to: &[u8; 32], share: &[u8; SHARE_BYTES]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/epoch-deal/commit/v1");
    h.update(vid);
    h.update(&epoch.to_le_bytes());
    h.update(to);
    h.update(share);
    *h.finalize().as_bytes()
}

fn stream(ss: &[u8], ct: &[u8]) -> [u8; SHARE_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/epoch-deal/stream/v1");
    h.update(ss);
    h.update(ct);
    let mut out = [0u8; SHARE_BYTES];
    h.finalize_xof().fill(&mut out);
    out
}

fn tag_of(ss: &[u8], body: &[u8]) -> [u8; TAG_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/epoch-deal/tag/v1");
    h.update(ss);
    h.update(body);
    let mut t = [0u8; TAG_BYTES];
    t.copy_from_slice(&h.finalize().as_bytes()[..TAG_BYTES]);
    t
}

/// Seal one share to a member's ML-KEM-768 encapsulation key: `ct ‖ tag ‖ masked share`.
#[must_use]
pub fn seal_share(ek: &[u8], share: &[u8; SHARE_BYTES]) -> Option<Vec<u8>> {
    let (ss, ct) = crate::pqkem::encapsulate(ek)?;
    let ks = stream(&ss, &ct);
    let body: Vec<u8> = share.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut out = ct;
    out.extend_from_slice(&tag_of(&ss, &body));
    out.extend_from_slice(&body);
    Some(out)
}

/// Open the share sealed to this member with its decapsulation key. `None` when it is not ours or malformed.
#[must_use]
pub fn open_share(dk: &[u8], sealed: &[u8]) -> Option<[u8; SHARE_BYTES]> {
    if sealed.len() != sealed_len() {
        return None;
    }
    let ct_len = crate::pqkem::ciphertext_len();
    let (ct, rest) = sealed.split_at(ct_len);
    let (tag, body) = rest.split_at(TAG_BYTES);
    let ss = crate::pqkem::decapsulate(ct, dk)?;
    if tag_of(&ss, body) != tag {
        return None;
    }
    let ks = stream(&ss, ct);
    let mut out = [0u8; SHARE_BYTES];
    for (o, (b, k)) in out.iter_mut().zip(body.iter().zip(ks.iter())) {
        *o = b ^ k;
    }
    Some(out)
}

impl EpochKeyDealTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::EpochKeyDeal, &self.encode())
    }
    /// One canonical encoding; exact widths for the public part, every sealed share and the key; a public part whose every
    /// coefficient lies in [0, q); 1 ..= `PEG_ATTEST_SEALED_MAX` shares to distinct recipients.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<EpochKeyDealTx> {
        let t: EpochKeyDealTx = crate::chain_object::decode_exact(bytes)?;
        let widths = t.pubkey.len() == crate::theft_tx::ML_DSA_65_PK_BYTES
            && t.sig.len() == crate::theft_tx::ML_DSA_65_SIG_BYTES
            && crate::epoch_key::unpack_b(&t.b).is_some()
            && !t.shares.is_empty()
            && t.shares.len() <= crate::peg_attest::PEG_ATTEST_SEALED_MAX
            && t.shares.iter().all(|s| s.sealed.len() == sealed_len());
        let distinct = t.shares.windows(2).all(|w| w[0].to < w[1].to);
        (widths && distinct).then_some(t)
    }
    /// The stateless half: the key is the vid's and it signed every field.
    #[must_use]
    pub fn authorised(&self) -> bool {
        crate::pqauth::pubkey_id(&self.pubkey) == self.vid
            && crate::pqauth::ml_dsa_verify(&deal_msg(&self.vid, self.epoch, &self.b, &self.shares), &self.pubkey, &self.sig)
    }
}

/// Build and sign a custodian's deal for `epoch` to `roster` (sorted `(id, ML-KEM ek)`): the public part from `seed`, the
/// seed's Shamir shares (t = ⌈2n/3⌉, coefficients from `coeffs`, `(t − 1)·32` bytes of fresh entropy) sealed per member.
#[must_use]
pub fn build(
    vote_pk: &[u8],
    vote_sk: &[u8],
    epoch: u64,
    roster: &[([u8; 32], Vec<u8>)],
    seed: &[u8; 32],
    coeffs: &[u8],
) -> Option<EpochKeyDealTx> {
    build_with_plain(vote_pk, vote_sk, epoch, roster, seed, coeffs).map(|(t, _)| t)
}

/// [`build`], also returning each roster member's plaintext share in roster order (the dealer's own view; a fraud pin
/// builds its evidence from it).
#[allow(clippy::type_complexity)]
pub fn build_with_plain(
    vote_pk: &[u8],
    vote_sk: &[u8],
    epoch: u64,
    roster: &[([u8; 32], Vec<u8>)],
    seed: &[u8; 32],
    coeffs: &[u8],
) -> Option<(EpochKeyDealTx, Vec<[u8; SHARE_BYTES]>)> {
    let vid = crate::pqauth::pubkey_id(vote_pk);
    let n = roster.len();
    let t = crate::shamir::two_thirds_threshold(n);
    let (_, part) = crate::epoch_key::deal(&matrix_seed(epoch), seed);
    let pieces = crate::shamir::split(seed, t, n, coeffs)?;
    let mut shares = Vec::with_capacity(n);
    let mut plains = Vec::with_capacity(n);
    for ((to, ek), p) in roster.iter().zip(pieces) {
        let mut plain = [0u8; SHARE_BYTES];
        plain[0] = p.x;
        plain[1..].copy_from_slice(&p.y);
        shares.push(SealedShare { to: *to, sealed: seal_share(ek, &plain)?, commit: share_commit(&vid, epoch, to, &plain) });
        plains.push(plain);
    }
    let b = crate::epoch_key::pack_b(&part);
    let sig = crate::pqauth::ml_dsa_sign(&deal_msg(&vid, epoch, &b, &shares), vote_sk)?;
    Some((EpochKeyDealTx { vid, epoch, b, shares, pubkey: vote_pk.to_vec(), sig }, plains))
}

/// One dealer's record in an epoch: what the release check and the fraud proof open against.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealRecord {
    /// blake3 of the dealer's packed public part (the release recomputes b_i from the rebuilt seed and compares).
    pub b_hash: [u8; 32],
    /// The dealer's commitment to each roster member's plaintext share, in roster order.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — one per roster member, at most `PEG_ATTEST_SEALED_MAX`.
    pub commits: Vec<[u8; 32]>,
}

/// One epoch's key state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRound {
    /// The RECIPIENTS: the bonded custodians SELECTED for work when the epoch's dealing hour opened (§22 2: a seat idle for
    /// more than two hours is not drawn), sorted by id — every deal addresses exactly these.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most `PEG_ATTEST_SEALED_MAX` ids.
    pub roster: Vec<[u8; 32]>,
    /// ⭐ §22 2 — the ELIGIBLE DEALERS: every custodian seated then, benched or not. Dealing is each seat's hourly heartbeat,
    /// so a benched seat that comes back deals, is seen active, and is drawn again the next hour.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most `PEG_ATTEST_SEALED_MAX` ids.
    pub eligible: Vec<[u8; 32]>,
    /// Σ b_i over the epoch's dealers, `K·N` coefficients in [0, q) — EMPTY until the first deal (MEASURED 2026-11-01: the
    /// bootstrap's 26 open rounds at 6 KB each, serialised into the peg words at every fold step, made the shipped cash-out
    /// sim's node ~10× slower on the wallet's book pass, 305 → 4,165 ms; an undealt round now costs ~100 B).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — empty or exactly `epoch_key::K * epoch_key::N` words.
    pub b_sum: Vec<u32>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most one per roster member.
    pub dealers: BTreeMap<[u8; 32], DealRecord>,
    /// ⭐ §19.3 bootstrap — the epoch the round was opened in: its DEALING HOUR. A deal applies only while the fold stands in
    /// it, and the key is final (sealable) from the next epoch on, so no ticket is ever sealed to a key a later deal changes.
    pub opened_in: u64,
}

/// ⭐ THE EPOCH-KEY LEDGER — a function of the canonical fold: the epochs [current − 1, current + DEAL_LEAD_EPOCHS], each
/// with its roster, its summed public key and its dealers. The epoch that just ended is kept for its batch-aligned release
/// (§19.4: custody opens epoch e only at the batch ending it, and verifies every dealer against this round). NO-GROWTH: at
/// most 28 epochs; an epoch is pruned at the first fold step two epochs after it (§19 item 6, the public half of erasure).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyLedger {
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — at most DEAL_LEAD_EPOCHS + 2 epochs (pruned every epoch).
    pub epochs: BTreeMap<u64, EpochRound>,
    /// The epoch the fold last stood in, plus one (0 = never ticked).
    pub current_next: u64,
    /// The epoch of the ledger's FIRST tick (the chain's first hour): custody releases the key of the epoch after it from the
    /// chain's first minutes ([`Self::first_released`]). Epochs count hours of chain time since 1970, so a chain's first epoch
    /// is its launch hour, never 0.
    #[serde(default)]
    pub first_epoch: u64,
    /// ⭐ §22 1 — activity as chain state: each custodian's last active hour and its uptime, moved by this ledger's tick (the
    /// window clock) and its deals (the heartbeat).
    pub activity: crate::validator_activity::ActivityLedger,
}

impl EpochKeyLedger {
    /// The epoch the fold stands in, once it has ticked.
    #[must_use]
    pub fn current(&self) -> Option<u64> {
        self.current_next.checked_sub(1)
    }
    /// The first epoch whose key custody releases: the one after the ledger's first tick (a chain's first deals are for it).
    #[must_use]
    pub fn first_released(&self) -> u64 {
        self.first_epoch + 1
    }
    /// Does a fold step in `epoch` move the ledger: the first step of a later epoch, or — with custody seated now — a step
    /// at which some epoch of the lead has no round or one nobody was eligible to deal for (§19.3 bootstrap: a chain whose
    /// custody forms after its hour's first step opens its rounds at the next step, not next hour)?
    #[must_use]
    pub fn tick_due(&self, epoch: u64, roster_now: &[[u8; 32]]) -> bool {
        match self.current() {
            None => true,
            Some(c) if epoch > c => true,
            Some(c) => {
                // A-F41: …or the epoch custody releases now has no round, or one nobody dealt for whose dealing hour
                // passed (custody that formed after this hour's first step deals it now, not next hour)
                let release = c.saturating_sub(1).max(self.first_released());
                !roster_now.is_empty()
                    && ((c + 1..=c + deal_lead()).any(|e| self.epochs.get(&e).map_or(true, |r| r.eligible.is_empty()))
                        || (release <= c
                            && self.epochs.get(&release).map_or(true, |r| r.dealers.is_empty() && (r.opened_in < c || r.eligible.is_empty()))))
            }
        }
    }
    /// The first fold step of `epoch` (prune every epoch before the one that just ended) and every step at which a round
    /// of the lead is missing: open it with the custody set now.
    pub fn tick(&mut self, epoch: u64, roster_now: &[[u8; 32]]) {
        if !self.tick_due(epoch, roster_now) {
            return;
        }
        let new_epoch = self.current().map_or(true, |c| epoch > c);
        if self.current().is_none() {
            self.first_epoch = epoch;
        }
        if new_epoch {
            self.current_next = epoch + 1;
        }
        let mut eligible = roster_now.to_vec();
        eligible.sort_unstable();
        eligible.dedup();
        eligible.truncate(crate::peg_attest::PEG_ATTEST_SEALED_MAX);
        if new_epoch {
            self.epochs.retain(|e, _| *e + 1 >= epoch);
            self.activity.tick(epoch, &eligible);
        }
        // ⭐⭐ THE RELEASE SCHEDULE STARTS WHERE CUSTODY'S FIRST ROUNDS DO. `first_released` is "the epoch whose key custody
        // releases from the chain's first minutes", and the chain's first tick set it — but a chain whose custody forms LATER
        // than its first tick opened no round then, so the epochs it named never had a key and the first one to release sat
        // two epochs past custody's first rounds. MEASURED 2026-11-09 (real nodes, landed main): btc_bridge and xmr_bridge each
        // launched with no custody, bonded it in the second hour, and both nodes answered every fast cash-out NO_EPOCH_KEY_YET
        // 50 minutes later; the sold pieces sat staged until the checks' 1,200 s ran out (nothing burned, nothing lost), and the
        // same cause explains btc_bridge passing 4 of 13 runs on 11/07-08 (only those whose custody formed inside the first hour).
        // A ledger holding no round (a chain's first custody, or custody back after every round was erased) starts its schedule
        // at the tick that opens its first rounds; a founding launch (custody at the first tick) is unchanged. Folded on every
        // node from the chain alone. BORROWED: the ledger's own first-key rule ("released from the chain's first minutes",
        // `release_epoch`), applied from custody's start — as Kaspa's pruning point and Bitcoin's checkpoints start at the
        // first state that has what they need, not at height 0. cons: the first released key serves up to three epochs, as it
        // already does for a founding launch; nothing else changes.
        if self.epochs.is_empty() && !eligible.is_empty() {
            self.first_epoch = epoch;
        }
        // §22 2: recipients are the seats SELECTED now; if none is (a chain whose custody was all away), every seat is — the
        // key schedule never stops for want of a roster
        let selected: Vec<[u8; 32]> = eligible.iter().copied().filter(|id| self.activity.selected(id, epoch)).collect();
        let roster = if selected.is_empty() { eligible.clone() } else { selected };
        // ⭐ §19.3 bootstrap (lane funds-brb26): every epoch in (epoch, epoch + lead] with no round — all of them on a chain's
        // first tick, or when a custody set first forms — or whose dealing hour passed with nobody dealing (a roster that was
        // empty or all away) is (re)opened over the custody set NOW, so a new chain has final keys as soon as its custody deals
        // instead of its 27th. In the steady state only epoch + lead is missing: one new round per tick, as before.
        // ⭐⭐ A-F41 (lane vaults, 2026-11-11) — THE EPOCH CUSTODY RELEASES NOW IS NEVER LEFT WITHOUT A ROUND TO DEAL FOR.
        // MEASURED on two real nodes (xmr_bridge.py, binary cf776a21, 22:40 to 23:34): custody's first seat landed seven
        // minutes before the chain hour ended; its 26 deals were pooled at once and the one for the first released epoch
        // had not folded when the hour ticked. That epoch was then the RUNNING one: the loop below never reaches it
        // (`e > epoch`), `refusal` turned its deal away for good ("its epoch is not one dealing now"), its round kept no
        // dealer, and `release_key` had nothing to give for the two hours the release schedule stands on it — both nodes
        // answered every fast cash-out NO_EPOCH_KEY_YET and the sold piece sat staged (nothing burned, nothing lost; the
        // holder's sale could not start). The same holds for any hour whose release round nobody dealt for.
        // So the release epoch's round is in the set this tick (re)opens, by the SAME rule as the lead's: no round, or
        // nobody dealt and its dealing hour passed (or nobody was eligible). Dealt late it is released by `release_key`'s
        // own rule — once every eligible dealer has dealt, or at the next hour with whoever did. Nothing else moves: no
        // ticket ever seals to an epoch at or under the running one (`public_key`), so a key dealt late was never a
        // sealing key; a round that HAS a dealer is never reopened (its key stays the one that was sealed to); the
        // normal schedule, the erasure and the lead are as they were. Folded on every node from the chain alone.
        // BORROWED: this ledger's own bootstrap rule (§19.3: a round nobody dealt for is reopened over the custody set
        // now), applied to the one round the schedule needs first. cons: a release key dealt late serves from the minute
        // its last eligible deal folds instead of from the hour's first step; one more round's deals (26 + 1) in such
        // an hour.
        let release = epoch.saturating_sub(1).max(self.first_released());
        for e in (release..=release).filter(|r| *r <= epoch).chain(epoch + 1..=epoch + deal_lead()) {
            let reopen = match self.epochs.get(&e) {
                None => true,
                Some(r) => r.dealers.is_empty() && (r.opened_in < epoch || r.eligible.is_empty()),
            };
            if reopen && !eligible.is_empty() {
                self.epochs.insert(
                    e,
                    EpochRound {
                        roster: roster.clone(),
                        eligible: eligible.clone(),
                        b_sum: Vec::new(),
                        dealers: BTreeMap::new(),
                        opened_in: epoch,
                    },
                );
            }
        }
    }
    /// The epochs whose dealing hour is now (the fold stands in their `opened_in`): the ones a custodian may deal for —
    /// the lead's, and (A-F41) the epoch custody releases now when its round was opened this hour for want of a dealer.
    #[must_use]
    pub fn dealing(&self) -> Vec<u64> {
        let Some(c) = self.current() else { return Vec::new() };
        self.epochs.iter().filter(|(e, r)| self.deals_now(**e, r, c)).map(|(e, _)| *e).collect()
    }
    /// THE ONE RULE for "this round takes deals at the fold step now standing in epoch `c`": it was opened in `c`, and it
    /// is an epoch of the lead (after `c`) or the epoch custody releases now. Read by the builder's list ([`Self::dealing`])
    /// and by the fold's door ([`Self::refusal`]), so a custodian never builds a deal the fold refuses for its epoch.
    fn deals_now(&self, epoch: u64, round: &EpochRound, c: u64) -> bool {
        round.opened_in == c && (epoch > c || self.release_epoch() == Some(epoch))
    }
    /// The ledger's rule for a deal: its epoch is the one now dealing, its dealer sits on that roster and has not dealt,
    /// and it addresses exactly the roster, in order. `None` = it applies.
    #[must_use]
    pub fn refusal(&self, t: &EpochKeyDealTx) -> Option<&'static str> {
        let Some(c) = self.current() else { return Some("the fold has not opened an epoch") };
        let Some(r) = self.epochs.get(&t.epoch) else { return Some("its epoch has no roster") };
        if !self.deals_now(t.epoch, r, c) {
            return Some("its epoch is not one dealing now");
        }
        if r.eligible.binary_search(&t.vid).is_err() {
            return Some("its dealer is not on the epoch's roster");
        }
        if r.dealers.contains_key(&t.vid) {
            return Some("its dealer has already dealt for this epoch");
        }
        if t.shares.len() != r.roster.len() || t.shares.iter().zip(&r.roster).any(|(s, id)| s.to != *id) {
            return Some("it does not address exactly the epoch's roster");
        }
        None
    }
    /// Apply a decided deal: add its public part to the epoch's key and record the dealer.
    pub fn observe_deal(&mut self, t: &EpochKeyDealTx) {
        let Some(part) = crate::epoch_key::unpack_b(&t.b) else { return };
        let Some(r) = self.epochs.get_mut(&t.epoch) else { return };
        if r.b_sum.is_empty() {
            r.b_sum = vec![0u32; crate::epoch_key::K * crate::epoch_key::N];
        }
        for (acc, c) in r.b_sum.iter_mut().zip(part.b.iter().flatten()) {
            *acc = ((u64::from(*acc) + u64::from(*c)) % u64::from(crate::epoch_key::Q)) as u32;
        }
        r.dealers.insert(t.vid, DealRecord { b_hash: *blake3::hash(&t.b).as_bytes(), commits: t.shares.iter().map(|s| s.commit).collect() });
        // §22 1: a deal is its dealer's heartbeat for the hour the fold stands in
        if let Some(c) = self.current() {
            self.activity.observe(&t.vid, c);
        }
    }
    /// The FINAL public key of `epoch` for SEALING (its dealing hour has passed and it has not begun, and someone dealt). A
    /// ticket encrypts to this; `None` while the epoch is still dealing, once it has begun, or when empty.
    #[must_use]
    pub fn public_key(&self, epoch: u64) -> Option<crate::epoch_key::EpochPublicKey> {
        let c = self.current()?;
        // final = a deal can no longer change it (its dealing hour has passed, or every eligible dealer has dealt — the
        // ledger refuses a second deal by any of them, so nothing more can sum) and the epoch has not begun
        let r = self.epochs.get(&epoch)?;
        let closed = r.opened_in < c || (!r.eligible.is_empty() && r.eligible.iter().all(|id| r.dealers.contains_key(id)));
        if epoch <= c || epoch > c + deal_lead() || !closed {
            return None;
        }
        self.key_of(epoch)
    }
    /// ⭐ §19.3 — the epoch a cash-out piece paying after `pay_after` (chain-time ms) seals to: the FIRST epoch with a final
    /// key at or after the one `pay_after` falls in (never a running one: its key opens at its batch, never earlier), and never
    /// [`Self::first_released`], whose key is released from the chain's first minutes. `None` = no final key within the lead (a
    /// chain's first minutes) — the request is refused, never sealed to a moving key.
    #[must_use]
    pub fn sealing_epoch(&self, pay_after: u64) -> Option<(u64, crate::epoch_key::EpochPublicKey)> {
        let c = self.current()?;
        (epoch_of(pay_after).max(c + 1).max(self.first_released() + 1)..=c + deal_lead()).find_map(|e| self.public_key(e).map(|pk| (e, pk)))
    }
    /// ⭐ The epoch custody releases now: the one that just ended, and from a chain's start [`Self::first_released`], so the sealed batch trades from the
    /// launch's first minutes instead of its third epoch (MEASURED 2026-11-04, real nodes: every founding custodian had dealt epoch 1 within minutes, and orders were refused for
    /// want of a key that was two epochs off: 14,400 blocks, 2 hours at the target and over 30 at today's block rate). Orders seal to this epoch's key.
    /// Cons: that one key serves for up to three epochs, not one, and only orders use it: no ticket ever seals to it ([`Self::sealing_epoch`]), and it is erased on the usual schedule.
    #[must_use]
    pub fn release_epoch(&self) -> Option<u64> {
        Some(self.current()?.saturating_sub(1).max(self.first_released()))
    }
    /// ⭐ §19.4 — the key custody may RELEASE `epoch` against: only the epoch [`Self::release_epoch`] names, once a deal can no longer change it. `None` for any other
    /// epoch, while dealers are still owed, and once its round is pruned.
    #[must_use]
    pub fn release_key(&self, epoch: u64) -> Option<crate::epoch_key::EpochPublicKey> {
        let c = self.current()?;
        if self.release_epoch()? != epoch {
            return None;
        }
        let r = self.epochs.get(&epoch)?;
        if !(r.opened_in < c || (!r.eligible.is_empty() && r.eligible.iter().all(|id| r.dealers.contains_key(id)))) {
            return None;
        }
        self.key_of(epoch)
    }
    fn key_of(&self, epoch: u64) -> Option<crate::epoch_key::EpochPublicKey> {
        let r = self.epochs.get(&epoch)?;
        // a sum of any other width (an adopted bundle's, say) is no key: `encapsulate` indexes all K ring elements
        if r.dealers.is_empty() || r.b_sum.len() != crate::epoch_key::K * crate::epoch_key::N {
            return None;
        }
        let b = r.b_sum.chunks_exact(crate::epoch_key::N).map(|c| std::array::from_fn(|i| c[i])).collect();
        Some(crate::epoch_key::EpochPublicKey { seed: matrix_seed(epoch), b, contributors: r.dealers.len() as u32 })
    }
}

/// What applying a deal at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum DealApply {
    NotDeal,
    Applied,
    Refused(&'static str),
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A custody set of `n` validators: (id, vote pk, vote sk, custody ek, custody dk), sorted by id.
    fn custody(n: usize) -> Vec<([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut v: Vec<_> = (0..n)
            .map(|_| {
                let (pk, sk) = crate::pqauth::ml_dsa_keypair();
                let (ek, dk) = crate::validator::custody_kem_from_vote_sk(&sk);
                (crate::pqauth::pubkey_id(&pk), pk, sk, ek, dk)
            })
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn entropy(tag: u8, i: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new().update(&[tag, i as u8]).finalize_xof().fill(&mut out);
        out
    }

    fn deal_by(c: &[([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)], i: usize, epoch: u64) -> EpochKeyDealTx {
        let roster: Vec<([u8; 32], Vec<u8>)> = c.iter().map(|m| (m.0, m.3.clone())).collect();
        let t = crate::shamir::two_thirds_threshold(c.len());
        let seed: [u8; 32] = entropy(1, i, 32).try_into().unwrap();
        build(&c[i].1, &c[i].2, epoch, &roster, &seed, &entropy(2, i, (t - 1) * 32)).expect("a deal")
    }

    /// ⭐⭐⭐ §22 2 — A SEAT IDLE TWO HOURS IS STILL DRAWN; A THIRD IDLE HOUR BENCHES IT FROM THE RECIPIENTS — YET IT STAYS AN
    /// ELIGIBLE DEALER, AND ONE DEAL (ITS HEARTBEAT) DRAWS IT AGAIN THE NEXT HOUR. Member 3 never deals for hours 100..=102.
    /// TWO-PARTY-REVIEWED: the ledger's rule over its own state; its crossing (two nodes folding the same deals and ticks to one
    /// ledger) is pinned in node::pins::a_validator_inactive_for_seven_days_is_unbonded_without_slash_on_every_node.
    #[test]
    fn br22_a_quiet_seat_leaves_the_recipients_keeps_dealing_and_one_deal_draws_it_again() {
        let c = custody(4);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let deal_to = |i: usize, epoch: u64, roster: &[[u8; 32]]| {
            let r: Vec<([u8; 32], Vec<u8>)> = c.iter().filter(|m| roster.contains(&m.0)).map(|m| (m.0, m.3.clone())).collect();
            let t = crate::shamir::two_thirds_threshold(r.len());
            let seed: [u8; 32] = entropy(7, i, 32).try_into().unwrap();
            build(&c[i].1, &c[i].2, epoch, &r, &seed, &entropy(8, i, t.saturating_sub(1) * 32)).expect("a deal")
        };
        let mut l = EpochKeyLedger::default();
        for h in 100..=103u64 {
            l.tick(h, &ids);
            let e = h + DEAL_LEAD_EPOCHS;
            let roster = l.epochs[&e].roster.clone();
            assert_eq!(l.epochs[&e].eligible, ids, "hour {h}: every seated custodian may deal");
            if h < 103 {
                assert_eq!(roster, ids, "hour {h}: idle for {} complete hour(s), member 3 is still drawn", h - 100);
            } else {
                assert!(!roster.contains(&ids[3]) && roster.len() == 3, "hour 103: a third idle hour benches member 3");
            }
            for i in 0..3 {
                let t = deal_to(i, e, &roster);
                assert_eq!(l.refusal(&t), None);
                l.observe_deal(&t);
            }
        }
        // member 3 comes back: it may deal though benched, and the deal is its heartbeat
        let e = 103 + DEAL_LEAD_EPOCHS;
        let back = deal_to(3, e, &l.epochs[&e].roster.clone());
        assert_eq!(l.refusal(&back), None, "⛔ a benched seat could not deal its way back");
        l.observe_deal(&back);
        l.tick(104, &ids);
        assert_eq!(l.epochs[&(104 + DEAL_LEAD_EPOCHS)].roster, ids, "one deal draws member 3 again the next hour");
        assert_eq!(l.activity.uptime(&ids[3], 104), Some((1, 5)), "member 3 was active one hour of five");
        assert_eq!(l.activity.uptime(&ids[0], 104), Some((4, 5)));
        // a stranger is never eligible
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let r: Vec<([u8; 32], Vec<u8>)> = c.iter().map(|m| (m.0, m.3.clone())).collect();
        let stranger = build(&pk, &sk, 104 + DEAL_LEAD_EPOCHS, &r, &[9; 32], &vec![1u8; 2 * 32]).expect("a deal");
        assert_eq!(l.refusal(&stranger), Some("its dealer is not on the epoch's roster"));
    }

    /// ⭐ §BR-9a step (b) — THE EPOCH KEY IS ONE FUNCTION OF THE DEALS: a producer's ledger and a PEER's ledger, each fed the
    /// same deals in a DIFFERENT order through the encoded wire bytes, hold the identical ledger and the identical final key —
    /// and that key is exactly the sum of the dealers' public parts (`epoch_key::combine_public`). The key is withheld
    /// while its epoch is still dealing and published from the next epoch on.
    #[test]
    fn br9a_b_two_ledgers_fed_the_same_deals_in_any_order_hold_one_epoch_key() {
        let c = custody(4);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let (mut producer, mut peer) = (EpochKeyLedger::default(), EpochKeyLedger::default());
        producer.tick(100, &ids);
        peer.tick(100, &ids);
        let e = 100 + DEAL_LEAD_EPOCHS;
        let deals: Vec<Vec<u8>> = (0..4).map(|i| deal_by(&c, i, e).encode()).collect();
        for w in &deals {
            let t = EpochKeyDealTx::decode(w).expect("decodes");
            assert!(t.authorised());
            assert_eq!(producer.refusal(&t), None);
            producer.observe_deal(&t);
        }
        for (i, w) in deals.iter().rev().enumerate() {
            let t = EpochKeyDealTx::decode(w).unwrap();
            if i == 3 {
                assert!(peer.public_key(e).is_none(), "a key still dealing (three of four dealt) is never published");
            }
            assert_eq!(peer.refusal(&t), None);
            peer.observe_deal(&t);
        }
        assert_eq!(producer, peer, "the peer folds the same deals in another order to the same ledger");
        assert!(producer.public_key(e).is_some(), "every eligible dealer dealt: nothing more can sum, the key is final at once");
        producer.tick(101, &ids);
        peer.tick(101, &ids);
        let key = producer.public_key(e).expect("final from the next epoch");
        assert_eq!(peer.public_key(e), Some(key.clone()));
        let parts: Vec<crate::epoch_key::PublicPart> =
            deals.iter().map(|w| crate::epoch_key::unpack_b(&EpochKeyDealTx::decode(w).unwrap().b).unwrap()).collect();
        assert_eq!(key, crate::epoch_key::combine_public(&matrix_seed(e), &parts));
        assert_eq!(key.contributors, 4);
    }

    /// ⭐ §BR-9a step (b) — EACH RECIPIENT OPENS ONLY ITS OWN SHARE, AND t SHARES REBUILD THE DEALER'S EXACT PUBLIC PART.
    /// Every roster member (a separate key holder) opens the share sealed to it and finds it under the dealer's signed
    /// commitment; no member opens another's. Any t members' shares rebuild the dealer's seed, and the seed re-derives the
    /// dealer's published b byte for byte — the release check §19.1 item 2 makes per dealer.
    #[test]
    fn br9a_b_each_recipient_opens_only_its_share_and_t_shares_rebuild_the_dealers_public_part() {
        let c = custody(5);
        let e = 9;
        let t = crate::shamir::two_thirds_threshold(5);
        let deal = EpochKeyDealTx::decode(&deal_by(&c, 2, e).encode()).unwrap();
        let mut opened = Vec::new();
        for (j, m) in c.iter().enumerate() {
            let mine = open_share(&m.4, &deal.shares[j].sealed).expect("the recipient opens its own share");
            assert_eq!(share_commit(&deal.vid, e, &m.0, &mine), deal.shares[j].commit, "under the dealer's commitment");
            let other = (j + 1) % c.len();
            assert!(open_share(&m.4, &deal.shares[other].sealed).is_none(), "and never another member's");
            opened.push(crate::shamir::Share { x: mine[0], y: mine[1..].to_vec() });
        }
        let seed: [u8; 32] = crate::shamir::combine(&opened[1..1 + t]).unwrap().try_into().unwrap();
        let (_, rebuilt) = crate::epoch_key::deal(&matrix_seed(e), &seed);
        assert_eq!(crate::epoch_key::pack_b(&rebuilt), deal.b, "the seed rebuilds the dealer's published public part");
    }

    /// ⭐ §BR-9a step (b) TAMPERS — the ledger refuses a deal for an epoch not dealing now, by a dealer off the roster, a
    /// second deal by the same dealer, and a deal that skips a roster member; the signature refuses a field changed after
    /// signing and a deal under another custodian's key; decode refuses a ragged public part.
    #[test]
    fn br9a_b_a_deal_off_window_off_roster_twice_misaddressed_or_altered_is_refused() {
        let c = custody(4);
        let outsider = custody(1);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let mut l = EpochKeyLedger::default();
        l.tick(50, &ids);
        let e = 50 + DEAL_LEAD_EPOCHS;
        assert_eq!(l.refusal(&deal_by(&c, 0, e + 1)), Some("its epoch has no roster"), "past the lead nothing is open");
        let mut rogue = outsider.clone();
        rogue.extend(c.iter().cloned());
        rogue.sort_by(|a, b| a.0.cmp(&b.0));
        let ri = rogue.iter().position(|m| m.0 == outsider[0].0).unwrap();
        assert_eq!(l.refusal(&deal_by(&rogue, ri, e)), Some("its dealer is not on the epoch's roster"));
        let good = deal_by(&c, 1, e);
        assert_eq!(l.refusal(&good), None);
        l.observe_deal(&good);
        assert_eq!(l.refusal(&good), Some("its dealer has already dealt for this epoch"));
        let mut skip = deal_by(&c, 2, e);
        skip.shares.pop();
        assert_eq!(l.refusal(&skip), Some("it does not address exactly the epoch's roster"));
        let mut altered = deal_by(&c, 3, e);
        altered.b[0] ^= 1;
        assert!(!altered.authorised(), "a public part changed after signing");
        let mut stolen = deal_by(&c, 3, e);
        stolen.pubkey = c[0].1.clone();
        assert!(!stolen.authorised(), "a deal under another custodian's key");
        let mut ragged = deal_by(&c, 3, e);
        ragged.b.pop();
        assert!(EpochKeyDealTx::decode(&ragged.encode()).is_none());
        // once its dealing hour has passed, the epoch takes no more deals (its key is final: no sealed ticket may move)
        l.tick(51, &ids);
        assert_eq!(l.refusal(&deal_by(&c, 2, e)), Some("its epoch is not one dealing now"), "⛔ a deal changed a final key");
    }

    /// ⭐ §19.3 BOOTSTRAP (lane funds-brb26) — A NEW CHAIN HAS A FINAL KEY FROM ITS SECOND HOUR, NOT ITS 27TH. The first tick
    /// opens every epoch of the lead over the custody set now; a deal made in that hour for the next-but-one epoch is final
    /// one tick later and is what a ticket seals to (`sealing_epoch`). A round nobody dealt for (custody away) is re-opened
    /// over the custody set at the next tick, so the schedule heals; a round that HAS dealers is never re-opened (its key
    /// stays the one tickets were sealed to). CALIBRATION: before any tick there is no key at all.
    #[test]
    fn br9a_c_a_new_chain_has_a_final_key_from_its_second_hour_and_an_undealt_round_reopens() {
        let c = custody(3);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let mut l = EpochKeyLedger::default();
        assert!(l.sealing_epoch(0).is_none(), "CALIBRATION: no key before the first tick");
        l.tick(0, &ids);
        assert_eq!(l.dealing(), (1..=DEAL_LEAD_EPOCHS).collect::<Vec<_>>(), "the first tick opens every epoch of the lead");
        for i in 0..3 {
            let d = deal_by(&c, i, 2);
            assert_eq!(l.refusal(&d), None, "a deal for the next-but-one epoch applies in the chain's first hour");
            l.observe_deal(&d);
        }
        // every eligible dealer has dealt: nothing more can sum into epoch 2, so its key is final inside the dealing hour
        let (e, pk) = l.sealing_epoch(0).expect("⛔ a fully-dealt key was withheld for the rest of its hour");
        assert_eq!((e, pk.contributors), (2, 3), "the fully-dealt epoch 2 seals; epoch 1, undealt, is skipped");
        assert!(l.public_key(1).is_none(), "an epoch still dealing is never sealed to");
        l.tick(1, &ids);
        let (e, pk) = l.sealing_epoch(1).expect("⛔ §19.3: no final key in the chain's second hour");
        assert_eq!((e, pk.contributors), (2, 3), "the second hour seals to epoch 2's three-dealer key");
        // epoch 3 was opened at 0 and nobody dealt: it re-opens at 1 (its dealing hour is now 1) and takes a deal
        assert_eq!(l.epochs[&3].opened_in, 1, "an undealt round re-opens over the custody set now");
        assert_eq!(l.refusal(&deal_by(&c, 0, 3)), None, "and takes a deal in its new dealing hour");
        assert_eq!(l.epochs[&2].opened_in, 0, "a dealt round is never re-opened");
        // custody that forms after an hour's first step: the rounds open at the next step, not next hour
        let mut late = EpochKeyLedger::default();
        late.tick(0, &[]);
        assert!(late.epochs.is_empty() && !late.tick_due(0, &[]), "no custody, no rounds, nothing due");
        assert!(late.tick_due(0, &ids), "⛔ §19.3: custody seated mid-hour had to wait for the next hour");
        late.tick(0, &ids);
        assert_eq!(late.dealing().len() as u64, DEAL_LEAD_EPOCHS, "every round of the lead opened at that step");
        assert!(!late.tick_due(0, &ids), "and nothing more is due in the hour");
        // an undealt round holds no key words (the bootstrap's 26 rounds cost ~100 B each, not 6 KB)
        assert!(l.epochs[&4].b_sum.is_empty() && l.epochs[&2].b_sum.len() == crate::epoch_key::K * crate::epoch_key::N);
        assert!(postcard::to_allocvec(&l.epochs[&4]).map_or(false, |b| b.len() < 256), "an undealt round serialises small");
    }

    /// ⭐ §BR-9a step (d), the public half — NO GROWTH BY CONSTRUCTION: whatever the epoch, after its first fold step the
    /// ledger holds only epochs in [E, E + DEAL_LEAD_EPOCHS] (every passed epoch's key, roster and records dropped). Checked at
    /// a small epoch and at one near the end of u64 — the held set is a function of E and the constant lead, never of how
    /// many epochs came before.
    #[test]
    fn br9a_d_the_ledger_holds_only_the_live_epochs_at_any_height() {
        let ids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        for (before, now) in [(5u64, 6u64), (5, 10_000), (1_000_000_000_000_000, 1_000_000_000_000_001)] {
            let mut l = EpochKeyLedger::default();
            l.tick(before, &ids);
            l.tick(now, &ids);
            // §19.4: the epoch that just ended is kept for its release at this batch; nothing older
            assert!(
                l.epochs.keys().all(|e| (now - 1..=now + DEAL_LEAD_EPOCHS).contains(e)),
                "at {now}: {:?}",
                l.epochs.keys()
            );
            assert!(l.epochs.contains_key(&(now + DEAL_LEAD_EPOCHS)), "at {now}: the dealing epoch opened");
            assert!(!l.tick_due(now, &ids), "a second step in the same epoch moves nothing");
        }
    }

    /// ⭐ THE FIRST KEY SERVES ORDERS FROM THE CHAIN'S FIRST MINUTES, AND ONLY ORDERS: released once every dealer has dealt it, before then nothing (a key a later deal could
    /// change is never released), never what a ticket seals to, and the normal schedule takes over at the third epoch. CALIBRATION: with one dealer owed, no key.
    #[test]
    fn the_first_key_opens_for_orders_once_every_dealer_dealt_and_no_ticket_ever_seals_to_it() {
        let c = custody(3);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let mut l = EpochKeyLedger::default();
        assert_eq!(l.release_epoch(), None, "no epoch before the first tick");
        l.tick(0, &ids);
        assert_eq!(l.release_epoch(), Some(l.first_released()), "from the first step, the first key is the one to release");
        for i in 0..2 {
            l.observe_deal(&deal_by(&c, i, 1));
            l.observe_deal(&deal_by(&c, i, 2));
            assert!(l.release_key(1).is_none(), "⛔ a key a later deal can change was released");
        }
        l.observe_deal(&deal_by(&c, 2, 1));
        l.observe_deal(&deal_by(&c, 2, 2));
        let pk = l.release_key(1).expect("⛔ every dealer dealt and the first key was withheld");
        assert_eq!(pk.contributors, 3, "all three dealers");
        assert_eq!(l.sealing_epoch(0).map(|(e, _)| e), Some(2), "⛔ a ticket sealed to the key orders already released");
        assert_eq!(l.sealing_epoch(1).map(|(e, _)| e), Some(2), "⛔ a ticket sealed to the key orders already released");
        l.tick(1, &ids);
        assert!(l.release_key(1).is_some(), "the first key serves the second epoch");
        assert!(l.release_key(2).is_none(), "⛔ the next key released early");
        l.tick(2, &ids);
        assert_eq!(l.release_epoch(), Some(1), "the third epoch is the first key's own batch");
        assert!(l.release_key(1).is_some(), "and the schedule is the normal one from here");
        l.tick(3, &ids);
        assert_eq!(l.release_epoch(), Some(2), "the normal schedule");
        assert!(l.release_key(1).is_none() && !l.epochs.contains_key(&1), "⛔ the first key outlived its erasure");
        assert!(l.release_key(2).is_some(), "the second key at its batch");
    }

    /// ⭐ MEASURED 2026-11-09 (btc_bridge on real nodes, landed main): a chain launched with no custody, whose custody bonded in
    /// its second hour, answered every fast cash-out with NO_EPOCH_KEY_YET 50 minutes after custody formed — its release
    /// schedule had started at the launch hour, whose epochs never got a round, so the first key to release was two hours off
    /// and the sold piece waited. The schedule starts where custody's first rounds do: the first of them releases once every
    /// eligible dealer has dealt it, minutes after custody forms, and no ticket ever seals to it. CALIBRATION: no custody, no
    /// round, no key; a dealer still owed, no key.
    #[test]
    fn a_chain_whose_custody_forms_after_its_first_hour_releases_a_key_once_custody_deals() {
        let c = custody(2);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let mut l = EpochKeyLedger::default();
        l.tick(10, &[]);
        assert!(l.epochs.is_empty(), "CALIBRATION: a launch with no custody opens no round");
        l.tick(11, &ids);
        assert_eq!(l.dealing().first().copied(), Some(12), "CALIBRATION: custody's first rounds start at the next epoch");
        assert_eq!(l.release_epoch(), Some(12), "⛔ the release schedule started at the launch hour, whose epochs have no round");
        l.observe_deal(&deal_by(&c, 0, 12));
        assert!(l.release_key(12).is_none(), "⛔ a key a later deal can change was released");
        l.observe_deal(&deal_by(&c, 1, 12));
        let pk = l.release_key(12).expect("⛔ custody dealt its first round and no key released: a fast cash-out waits two hours");
        assert_eq!(pk.contributors, 2, "both dealers");
        assert!(l.sealing_epoch(0).map_or(true, |(e, _)| e != 12), "⛔ a ticket sealed to the key orders already released");
        // a founding launch (custody at the first tick) is unchanged: its schedule starts at that tick
        let mut f = EpochKeyLedger::default();
        f.tick(10, &ids);
        assert_eq!(f.release_epoch(), Some(11), "a founding launch releases its first round, as before");
    }

    /// ⛔⛔ A-F41 (lane vaults, 2026-11-11) — MEASURED on two real nodes (xmr_bridge.py, binary cf776a21): custody formed
    /// seven minutes before the chain hour ended; its deals were pooled at once and the one for the first released epoch
    /// folded AFTER the hour ticked. That epoch was then the running one: its deal was refused for good, its round never
    /// had a dealer, and for the two hours the release schedule stands on it every fast cash-out was answered
    /// NO_EPOCH_KEY_YET (a sold $10 piece sat staged for the 1,500 s the check waits).
    /// The ledger's rule, at its own level: custody forms in hour 11 and NO deal folds before hour 12 begins.
    ///   • the epoch custody releases (12) takes its deal in hour 12, and its key is released once every eligible
    ///     dealer has dealt — minutes, not two hours;
    ///   • nothing else moved: no ticket seals to that key; a round that HAS a dealer is never reopened; a deal for a
    ///     running epoch that is NOT the release epoch is still refused; the normal schedule follows.
    ///   • one dealer of two never deals: the key waits out the hour and is released at the next with the one who did.
    ///   • CALIBRATION: custody whose deals folded inside hour 11 is exactly as before (nothing reopens, same key).
    /// TWO-PARTY-REVIEWED: the ledger's rule over its own state (two ledgers fed the same ticks and deals hold one key:
    /// `br9a_b_two_ledgers_fed_the_same_deals_in_any_order_hold_one_epoch_key`); the real-node proof is the bridge
    /// checks' sale on a rig whose custody forms late in an hour.
    #[test]
    fn af41_a_release_round_nobody_dealt_in_its_hour_takes_its_deal_late_and_releases_within_the_hour() {
        let c = custody(2);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let late = || {
            let mut l = EpochKeyLedger::default();
            l.tick(10, &[]);
            l.tick(11, &ids);
            assert_eq!(l.release_epoch(), Some(12), "PRECONDITION: custody's first round is the one to release");
            l.tick(12, &ids); // the hour ends with no deal folded
            l
        };
        let mut l = late();
        assert_eq!(l.release_epoch(), Some(12), "the schedule still stands on custody's first round");
        assert!(!l.tick_due(12, &ids), "the reopened round is not due again in the hour (no tick per fold step)");
        let d0 = deal_by(&c, 0, 12);
        assert_eq!(l.refusal(&d0), None, "⛔ A-F41: the deal for the epoch custody releases was refused for good once that epoch began — no key for two hours");
        assert!(l.dealing().contains(&12), "⛔ the builder's list does not name the release round: no custodian deals for it");
        l.observe_deal(&d0);
        assert!(l.release_key(12).is_none(), "⛔ a key a later deal can change was released");
        assert_eq!(l.refusal(&deal_by(&c, 0, 12)), Some("its dealer has already dealt for this epoch"), "a second deal by the same dealer is still refused");
        let d1 = deal_by(&c, 1, 12);
        assert_eq!(l.refusal(&d1), None);
        l.observe_deal(&d1);
        let pk = l.release_key(12).expect("⛔ every eligible dealer dealt the release round and no key was released");
        assert_eq!(pk.contributors, 2, "both dealers");
        assert!(l.public_key(12).is_none() && l.sealing_epoch(0).map_or(true, |(e, _)| e > 12), "⛔ a ticket sealed to a key dealt for the running epoch");
        // the lead's rounds reopened beside it, as they always did; the normal schedule follows
        assert_eq!(l.refusal(&deal_by(&c, 0, 13)), None, "the lead's undealt rounds take deals in the same hour");
        l.observe_deal(&deal_by(&c, 0, 13));
        l.observe_deal(&deal_by(&c, 1, 13));
        l.tick(13, &ids);
        assert!(l.release_key(12).is_some() && l.epochs[&12].opened_in == 12, "a dealt release round is never reopened");
        assert_eq!(l.refusal(&deal_by(&c, 0, 13)), Some("its epoch is not one dealing now"), "⛔ a deal for a running epoch that is not the release epoch was taken");
        l.tick(14, &ids);
        assert_eq!(l.release_epoch(), Some(13), "the normal schedule: the epoch that just ended");
        assert!(l.release_key(13).is_some_and(|k| k.contributors == 2));
        // one dealer of two never deals: the round waits out its hour, then releases with the one who did
        let mut one = late();
        one.observe_deal(&deal_by(&c, 0, 12));
        assert!(one.release_key(12).is_none(), "an eligible dealer is still owed inside the hour");
        one.tick(13, &ids);
        assert_eq!(one.epochs[&12].opened_in, 12, "a round with a dealer is not reopened");
        assert!(one.release_key(12).is_some_and(|k| k.contributors == 1), "⛔ the release key was withheld past its dealing hour");
        // nobody deals at all: the round reopens each hour it is the release round, and the lead moves on
        let mut none = late();
        none.tick(13, &ids);
        assert_eq!((none.release_epoch(), none.epochs[&12].opened_in), (Some(12), 13), "an undealt release round reopens again");
        // CALIBRATION: deals folded inside custody's own hour — nothing reopens, the same key is released
        let mut t = EpochKeyLedger::default();
        t.tick(10, &[]);
        t.tick(11, &ids);
        t.observe_deal(&deal_by(&c, 0, 12));
        t.observe_deal(&deal_by(&c, 1, 12));
        let key_before = t.release_key(12).expect("dealt in time");
        t.tick(12, &ids);
        assert_eq!(t.epochs[&12].opened_in, 11, "CALIBRATION: a round dealt in its hour is not reopened");
        assert_eq!(t.release_key(12).map(|k| k.contributors), Some(key_before.contributors));
        assert_eq!(t.refusal(&deal_by(&c, 0, 12)), Some("its epoch is not one dealing now"), "CALIBRATION: and takes no further deal");
    }

    /// ⭐ §19.4 — BATCH-ALIGNED RELEASE: an epoch's key may be released only by the batch at its END. While the fold stands
    /// in epoch e, `release_key(e)` is `None` (custody holds the shares but may not open the epoch); from the first fold step
    /// of e + 1 it is the epoch's key; an epoch two behind is gone (its round pruned). The ENCRYPTION key (`public_key`) of
    /// e is final before e begins and stops being offered once e begins (no ticket is sealed to a running epoch).
    #[test]
    fn br9a_c4_custody_opens_a_batch_only_at_its_end_and_not_one_epoch_early() {
        let c = custody(3);
        let ids: Vec<[u8; 32]> = c.iter().map(|m| m.0).collect();
        let mut l = EpochKeyLedger::default();
        l.tick(10, &ids);
        let e = 10 + DEAL_LEAD_EPOCHS;
        for i in 0..3 {
            let d = deal_by(&c, i, e);
            l.observe_deal(&d);
        }
        l.tick(11, &ids);
        assert!(l.public_key(e).is_some(), "final for sealing tickets well before the epoch");
        assert!(l.release_key(e).is_none(), "⛔ not releasable while the epoch is still in the future");
        l.tick(e, &ids);
        assert!(l.public_key(e).is_none(), "no ticket is sealed to a running epoch");
        assert!(l.release_key(e).is_none(), "⛔ §19.4: custody may not open the epoch while it runs — only at its batch");
        l.tick(e + 1, &ids);
        assert!(l.release_key(e).is_some(), "the batch at the epoch's end opens it");
        l.tick(e + 2, &ids);
        assert!(l.release_key(e).is_none() && !l.epochs.contains_key(&e), "two epochs on, the round is gone");
    }
}

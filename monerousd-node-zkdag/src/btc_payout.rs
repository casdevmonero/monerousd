// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ DB-121 (2026-09-20) — THE BITCOIN PAYOUT LANE: the peg's exit leg, end to end, with no signing session.
//!
//! WHAT IT DOES. A burn (`Class::PegOut`) that the chain has FINALIZED is an obligation: so many sats to the
//! destination the redeemer sealed to each custodian (DB-110). This lane pays it. One bonded custodian — the
//! proposer of the current slot — assembles a Bitcoin transaction from the reserve's own coins and gossips the
//! PROPOSAL (burn nullifiers, coins, fee, change nonce — never a destination). Every bonded custodian checks it
//! against ITS OWN book (opened from the blocks it applied), ITS OWN Bitcoin source and ITS OWN chain, signs each
//! input with its own key if it agrees, and gossips the signatures. Whoever holds a quorum's worth assembles the
//! `OP_CHECKSIGADD` witness (`btc_tx`) and hands the transaction to Bitcoin. When THIS node's own source has
//! watched it confirm, the burn is recorded released. No coordinator, no rounds, no key shares, nobody waits on
//! anybody: a custodian that is offline simply contributes no signature, and the k-of-n needs only a quorum. It is
//! the Bitcoin twin of the bond-weighted multisig tally that authorises every mint and burn.
//!
//! THE FLASH-LOAN CLASS, ARMOURED (DB-122 — user 2026-09-20 "add defense against flash loan attacks which plague
//! many bridges"), every guard a WAIT or an attack-only refusal, never a cap on honest flow:
//!   F1  a burn is paid only after the chain has FINALIZED its block (`finalized_height`), never on inclusion —
//!       a reorg of the burn block cannot leave USDm alive and BTC gone.
//!   F2  a reserve coin is spent, and a deposit counted, only after THORChain's confirmation counting
//!       (`btc_watch::required_confirmations`, ⌈value/subsidy⌉) — unwinding it costs more than it is worth.
//!   F4  one signature per burn per custodian (`Lock`): a second proposal for a burn this node already signed
//!       must CONFLICT with the first (share a coin), so two payouts can never both confirm below a ≥2/3
//!       collusion — with k = ⌈2/3⌉ of weight, two non-conflicting proposals would need an honest signer to sign
//!       both, and honest signers do not.
//!   F5  a release is recorded only when the PAYOUT has confirmed (same counting), never on broadcast.
//!   F6  SOLVENCY: every poll compares the coins this node's source sees at the reserve's addresses with the
//!       reserve total its own opening holds; fewer coins than the ledger says ⇒ this node refuses to attest NEW
//!       issuance (`Node::set_reserve_solvency_hold`) until they are seen — never a redemption, never a halt.
//!   F7  the fee a proposer names is bounded above by four times THIS signer's own fee estimate — a proposer
//!       cannot pay the reserve to miners.
//!   (DB-123, the inbound twin, lives in `Node::reserve_address_is_ours`: a deposit mints only at an address the
//!   custody script controls.)
//!
//! THE BOOK. What a custodian needs to pay — obligations, coin addresses with their nonce and leaf, the leaves
//! themselves, and its locks — is a Bitcoin WALLET's state: per coin, by Bitcoin's own construction, bounded by
//! the coins the reserve holds and cleared as they are spent. It lives in this external-chain module's own file
//! (`custody-book-<port>.bin` beside the validator key), never in the MonerousD snapshot: the node's own state
//! stays the O(1) proof + frontier it always was. Every entry is opened from a block this node applied
//! (`Node::drain_payout_events`), so a custodian that re-applies its blocks rebuilds the book.
//!
//! Borrowed shapes, cited: proposer rotation by height slot (Tendermint's round-robin proposer); one-signature-
//! per-item with conflict-only replacement (Bitcoin's RBF conflict rule, applied to the signer's own policy);
//! confirmation counting (THORChain); the k-of-n script (BIP 342 `multi_a`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::btc_tx::{self, CustodyLeaf, Payout, TxIn, TxOut, PAYOUT_INPUTS_MAX};
use crate::btc_watch::{btc_source, required_confirmations, BtcSource};
use crate::node::{Node, PayoutEvent};
use crate::peg_pool::{epoch_seed, payout_order_key, BATCH_MAX};
use crate::protocol::WireMsg;
use crate::spend_frontier::Digest4;

/// How often the lane reads Bitcoin (coins, confirmations, fees) and re-broadcasts. A fixed cadence, not a
/// deadline: nothing is decided when it elapses, the lane simply asks again.
/// PAST-CHATS-CHECKED: the peg lanes' own cadence, `peg_attest::PEG_ATTEST_REBROADCAST_MS` (10 s); same figure.
pub const PAYOUT_POLL_MS: u64 = crate::peg_attest::PEG_ATTEST_REBROADCAST_MS;
/// Proposer rotation: the custodian whose turn it is changes every minute of CHAIN TIME at the finalized block
/// (`Node::finalized_chain_time_ms`), so a silent proposer yields the duty and the payout never waits on one node. It is also
/// the payout grid a wallet draws its pieces' pay-afters on. It was 120 finalized blocks, "one minute at 500 ms"; the chain
/// has never run at that target (MEASURED 2026-11-08: about 5 blocks a minute, so a slot was 24 minutes), and a minute is the
/// same order as the peg lanes' 10 s re-broadcast cadence times a few misses.
pub const PROPOSER_SLOT_MS: u64 = 60_000;
/// How many payout proposals this node tracks at once — the peg attestation lanes' own bound.
/// PAST-CHATS-CHECKED: `peg_attest::PEG_ATTEST_PENDING_MAX`, reused rather than re-tuned.
pub const PAYOUT_SLOTS_MAX: usize = crate::peg_attest::PEG_ATTEST_PENDING_MAX;
/// Bitcoin Core's dust threshold — defined in [`crate::btc_tx::DUST_SATS`], with the Bitcoin transaction rules.
pub use crate::btc_tx::DUST_SATS;
/// A signer refuses a proposal whose fee exceeds this many times ITS OWN fee estimate (F7).
/// PAST-CHATS-CHECKED: no prior figure in the tree; the fee market's own 6-block estimate is the reference every
/// Bitcoin wallet uses, and four times it is where a "fee" stops reading as a fee and becomes a transfer to miners.
pub const FEE_CEIL_MULTIPLE: u64 = 4;

/// The Bitcoin outputs one burn's release is paid as — the ONE spelling the proposer's fee probe and every signer's
/// output build read, and what the §BR-0 linkability attacker (`bridge_linkability`) observes. Today it is ONE output
/// of exactly `release_sats`: an exit amount that names its burn (spec docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §3.1,
/// the amount link §BR-1 removes by paying standard pieces from the shared pool).
#[must_use]
pub fn payout_leg_outputs(release_sats: u64) -> Vec<u64> {
    vec![release_sats]
}

/// ⭐ A-F21 (lane dcash with lane speed, 2026-11-11) — THE BITCOIN MINER FEE IS PAID BY THE BURN, NEVER BY THE RESERVE.
/// FOUND (speed, read from the code on main ff11315e): a payout paid `legs + decoys + fee` out of reserve coins while the ledger's
/// reserve fell by the release alone, so after the first payout every custodian's coins read below its opening's reserve,
/// `solvency()` set its hold and every new Bitcoin deposit was refused; over many payouts the ledger's reserve drifted above the
/// coins that exist. Monero takes the fee out of its legs (`subtract_fee_from_outputs`); Bitcoin cannot shave each leg by its own
/// share, because exits of one rung must pay one amount (the crowd, `decoy_tx::CROWD_FLOOR`) and decoys mirror that amount.
/// THE RULE (A-F35, lane vaults 2026-11-11, replacing the fixed 2,000-sat allowance this rule first shipped with): THE LEGS OF A
/// BATCH PAY ITS FEE IN EQUAL SHARES. A leg pays its release less `⌈fee / legs⌉` ([`leg_fee_share`], [`leg_paid_sats`]); decoys
/// pay the legs' paid amount; every signer recomputes the share from the proposal's own fee and leg count. The ledger's reserve
/// already fell by the full release when the cash-out's own chain object folded (`PegLedger::opening_after_peg_out`,
/// unchanged), so the coins that leave custody never exceed what the ledger already took off — the shares cover the whole fee
/// by construction — and the rounding (under one sat per leg) stays in the reserve as cover.
/// CACHE-ONLY: these are pure functions of a proposal's own figures, read by the proposer and by every signer; nothing here
/// moves chain state (the cash-out is the chain object, applied at its fold; the payout is a Bitcoin transaction).
/// WHY NOT A FIXED ALLOWANCE. MEASURED on real nodes (btc_bridge.py, binary 449ac450, 2026-11-11 20:13): one $10 piece alone in
/// its batch, a fee of 2,626 sats at 2 sat/vB (a custody leaf's input is about 1,270 vB) against a 2,000-sat allowance — "not
/// proposing yet … the batch waits to fill or for the rate to fall". The cash-out is final on our chain, so the seller's USDm
/// was gone and its coins waited for other sellers: 9 pieces at 10 sat/vB, never from 47 sat/vB up. A cash-out must not wait
/// on strangers.
/// A PIECE NEVER LOSES MORE THAN HALF TO THE FEE ([`FEE_SHARE_MAX_DIVISOR`]): a leg whose share would pass half its release (or
/// leave under dust) is left out of the batch and waits for a lower rate or for company — the wallet says so before the sale.
/// Every signer still holds the fee itself to `[1 sat/vB, FEE_CEIL_MULTIPLE × its own reading]` (F7), so a proposer cannot
/// spend a seller's piece on an inflated fee.
/// cons: what a piece pays is no longer one figure known at the sale — it is the piece's share of the transaction that pays it,
/// at the Bitcoin fee rate of that moment (the wallet shows the alone-in-the-batch figure from its node's own reading, which is
/// the most a piece pays at that rate); two exits of one rung paid in different batches differ by their batches' shares, which
/// are public (each batch's fee and output count are on Bitcoin) — inside one batch every leg of a rung still pays one amount.
/// BORROWED: Bitcoin Core's `subtractfeefromamount` (the recipients pay the fee, split equally among them).
pub const FEE_SHARE_MAX_DIVISOR: u64 = 2;

/// Each leg's share of a batch's miner fee: `⌈fee / legs⌉`, the same for every leg of the batch. `None` for a batch with no leg.
#[must_use]
pub fn leg_fee_share(fee_sats: u64, legs: usize) -> Option<u64> {
    (legs > 0).then(|| fee_sats.div_ceil(legs as u64))
}

/// ⭐ A-F35 — WHAT ONE PIECE PAYS WHEN IT IS ALONE IN ITS BATCH, as `(vbytes, fee in sats)` at `rate` sat/vB: the fee of a
/// payout with one reserve coin under this node's vault's current key (its home leaf, else the live custody leaf), one leg
/// output and the change — the proposer's own probe (`propose`), so the figure a wallet shows before a sale is the figure
/// the lane would charge a lone piece at that rate; a piece that shares its batch pays less. `None` when no custody leaf
/// forms on this node's chain. CACHE-ONLY: a read of the chain's key record and a size estimate; it decides nothing.
#[must_use]
pub fn alone_fee_quote(node: &Node, rate: u64) -> Option<(u64, u64)> {
    let (leaf, _) = PayoutLane::change_target(node)?;
    let probe = Payout {
        inputs: vec![TxIn { txid: [0u8; 32], vout: 0, value_sats: 0, script_pubkey: vec![0x51, 0x20], sequence: 0 }],
        outputs: (0..2).map(|_| TxOut { value_sats: 0, script_pubkey: vec![0u8; 34] }).collect(),
    };
    let vbytes = probe.estimate_vbytes(&leaf);
    Some((vbytes, vbytes.saturating_mul(rate)))
}

/// What a Bitcoin leg of `release_sats` pays its recipient in a batch whose legs each carry `share` of the fee: the release less
/// the share. `None` when the share is more than half the release or what is left is under dust — that piece is not paid in
/// this batch (it waits; it is never paid short of the rule, and never out of the reserve).
#[must_use]
pub fn leg_paid_sats(release_sats: u64, share: u64) -> Option<u64> {
    (share <= release_sats / FEE_SHARE_MAX_DIVISOR).then(|| release_sats - share).filter(|p| *p >= DUST_SATS)
}

/// ONE rule for "may this piece be paid now", read by the proposer and by every signer (DB-122 F1's finality bound
/// plus §BR-1's sealed pay-after): a leg is payable only when its burn's height is at or below this node's finalized height
/// AND its sealed pay-after (chain-time ms) is at or below the chain clock at that finalized block
/// (`Node::finalized_chain_time_ms`). One site, two callers — a batch is never proposed with a leg a signer refuses.
#[must_use]
pub fn leg_is_payable(ob: &Obligation, finalized: u64, finalized_ms: u64) -> bool {
    ob.burn_height <= finalized && ob.pay_after <= finalized_ms
}

/// One burn's Bitcoin obligation, as THIS custodian opened it from the block that carried the burn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub release_sats: u64,
    pub redeem_to: String,
    pub burn_height: u64,
    /// §BR-1: the earliest finalized chain time (ms) this piece may be paid at — the sealed privacy delay. A leg is neither
    /// proposed nor signed before it (one more bound beside DB-122 F1's finality).
    #[serde(default)]
    pub pay_after: u64,
}

/// The one payout proposal this custodian signed for a burn, and the reserve coins it spends (F4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub proposal_id: [u8; 32],
    pub inputs: Vec<([u8; 32], u32)>,
}

/// What a payout needs to spend a reserve coin at an address: the per-deposit nonce that tweaked its internal
/// key (the mint blind's 64 lane bytes for a deposit, a payout's 32-byte change nonce for change), and the hash
/// of the custody leaf whose k-of-n script guards it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinAddress {
    pub nonce: Vec<u8>,
    pub leaf_hash: [u8; 32],
}

/// The custodian's Bitcoin book — a Bitcoin wallet's state, persisted in this module's own file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CustodyBook {
    pub obligations: BTreeMap<[u8; 32], Obligation>,
    pub locks: BTreeMap<[u8; 32], Lock>,
    pub addresses: BTreeMap<String, CoinAddress>,
    pub leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
    /// §BR-2: every minted CO-SIGNED deposit still to sweep, by its address — the depositor's authorization from the
    /// block's sealed leg. A deposit coin is never a payout input: it is swept (exactly the transaction the depositor
    /// signed) into a single-leaf reserve coin first, and its row leaves when the sweep settles.
    pub deposits: BTreeMap<String, DepositRec>,
    /// ⭐ §BR-5: every cash-out piece this custodian owes but cannot read until two thirds of custody release their shares.
    /// O1-INFINITY-REVIEWED: bounded by the burns in flight (a ticket leaves when it opens into an obligation).
    pub tickets: BTreeMap<[u8; 32], PendingTicket>,
    /// ⭐ SAFE AT SCALE, stage three — the consolidations this custodian saw confirmed whose fee the chain has not booked
    /// yet, by Bitcoin txid: the evidence (`CostEvidence`) the cost lane signs from. Kept in the file because a fee that
    /// left custody must reach the ledger whatever restarts in between (finding A-F21); an entry leaves when the chain
    /// books it. O1-INFINITY-REVIEWED: at most one entry per consolidation in flight (`COSTS_PENDING_MAX`).
    pub costs: BTreeMap<[u8; 32], Vec<u8>>,
    /// ⭐ OWED, the hand-over — for every cash-out this custodian booked and the chain still shows owed, the signed parts
    /// of its object (an encoded `peg_out_tx::LegProof`), by the burn's nullifier: what a vault mate that adopted after
    /// the cash-out's block left every body window is handed (`LegShare`). Kept in the file because the block is gone and
    /// a restart must not lose the only copies a vault holds.
    /// O1-INFINITY-REVIEWED: one entry per cash-out IN FLIGHT; it leaves when the chain shows the release paid.
    pub leg_proofs: BTreeMap<[u8; 32], Vec<u8>>,
}

/// The consolidations a book holds unbooked at once: one per replaced key of a vault and a few in flight.
pub const COSTS_PENDING_MAX: usize = 16;

/// ⭐ SAFE AT SCALE, stage three — WHAT A RESERVE COST'S SIGNERS JUDGE (the evidence a `ReserveCostSig` carries): the
/// consolidation proposal as it was signed, and for each input the nonce and custody leaf its address derives from.
/// With these any custodian of the vault — one that joined after the move, or was down through it — re-derives every
/// input address from a key ITS OWN chain records for the vault, rebuilds the transaction, and reads its inputs and
/// its depth from ITS OWN Bitcoin source (`PayoutLane::judge_cost`). Nothing in it is believed.
/// DIGITAL-CASH-PRIVACY-REVIEWED: reserve coins' own addresses and values (public on Bitcoin) and the nonces of
/// SWEPT or consolidated coins (a hash of a deposit's blind, never the blind); no user, note or destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostEvidence {
    pub proposal: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one per proposal input, at most `PAYOUT_INPUTS_MAX`.
    pub coins: Vec<CoinAddress>,
    /// ⭐ spec §3g.1 — a REBALANCE MOVE's first output as it was signed: `(sats, script)` — the part that left for the
    /// receiving vault, which the carve already took out of this vault's ledger; `None` for a consolidation. A judge reads
    /// the move's fee as the inputs' true total less this output and the change, so the part is never booked as a fee.
    /// O1-FOOTPRINT-REVIEWED: one 34-byte taproot script (`decode` refuses wider).
    pub rebalance_out: Option<(u64, Vec<u8>)>,
}

impl CostEvidence {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Bounded decode: one proposal and exactly one coin address per input, each nonce at most 64 bytes; a rebalance's
    /// output a taproot script of a value at least dust, on a proposal of exactly one leg (a consolidation names none).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<(PayoutProposal, Vec<CoinAddress>)> {
        Self::decode_full(bytes).map(|(p, c, _)| (p, c))
    }
    /// [`Self::decode`] with a rebalance move's first output.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn decode_full(bytes: &[u8]) -> Option<(PayoutProposal, Vec<CoinAddress>, Option<(u64, Vec<u8>)>)> {
        let e: Self = crate::chain_object::decode_exact(bytes)?;
        let p = PayoutProposal::decode(&e.proposal)?;
        let shaped = match &e.rebalance_out {
            None => p.legs.is_empty(),
            Some((v, spk)) => p.legs.len() == 1 && *v >= DUST_SATS && spk.len() == 34 && spk[..2] == [0x51, 0x20],
        };
        (shaped && e.coins.len() == p.inputs.len() && e.coins.iter().all(|c| c.nonce.len() <= 64)).then_some((p, e.coins, e.rebalance_out))
    }
}

/// The entries one coin-list answer carries (`CoinShare::Give`); a longer list goes out as several answers.
pub const COIN_SHARE_CHUNK: usize = 32;
/// The sealed body's bound: `COIN_SHARE_CHUNK` entries of a 64-byte nonce and a 32-byte leaf hash, with their lengths.
pub const COIN_SHARE_BODY_MAX: usize = COIN_SHARE_CHUNK * 100 + 8;
/// A custodian asks for its vault's coin list at most this often, and answers one asker at most this often.
pub const COIN_SHARE_EVERY_MS: u64 = 30_000;

/// ⭐ SAFE AT SCALE, stage three — A VAULT'S COIN LIST IS HANDED TO A CUSTODIAN THAT CANNOT SEE ITS VAULT'S COINS
/// (`WireMsg::CoinShare`). A deposit's reserve address is tweaked by a nonce only the custodians seated at its mint
/// received, so a custodian that joined later sees fewer coins than its opening counts: its solvency reading holds
/// its vault's deposits and it can judge no move of those coins. It ASKS (round `round`, so each ask is answered by
/// ONE custodian of the vault, the next in seat order each round — a withheld answer costs one round); the answer is
/// the nonce and leaf of every coin the giver's own source shows, sealed to the asker's registered custody ML-KEM key.
/// THE ASKER BELIEVES NOTHING: it books an entry only if the address derives under a key ITS OWN chain records for
/// its vault and ITS OWN source shows a coin there (BORROWED: this tree's `opening_share` — a share is taken only if
/// it verifies against public state; Feldman / Pedersen verifiable secret sharing).
/// §9.6 (a peer door): (1) no PoW — not a chain object, moves no chain state; (2) every entry is checked against
/// the chain's key record and the asker's own Bitcoin source; (3) value — none: an address with a coin under the
/// vault's own key; (4) a repeat books nothing new; (5) work — one answer per ask per giver per
/// `COIN_SHARE_EVERY_MS`, entries capped per message, one derivation and one source read per entry; (6) parity with
/// `OpeningShare::Give`: sealed to the registered key, taken only on its own check; (7) scale — one vault's
/// custodians, one giver per ask, bytes linear in the vault's coins; (8) a lying giver gains nothing (a garbage
/// entry derives no funded address); a persuasive message gains nothing (no claim is read, only derivable bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoinShare {
    /// The bonded custodian `from`, seated in vault `vault`, asks for that vault's coin list (ask number `round`).
    Ask { vault: u32, from: [u8; 32], round: u32 },
    /// Coin entries sealed to the bonded custodian `to`.
    Give { to: [u8; 32], sealed: Vec<u8> },
}

impl CoinShare {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// `None` for anything that is not exactly one message of this lane within its bounds.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(b)?;
        match &m {
            CoinShare::Give { sealed, .. } if sealed.len() > crate::pqkem::ciphertext_len() + 16 + COIN_SHARE_BODY_MAX => None,
            _ => Some(m),
        }
    }
}

/// A custodian asks its vault for one cash-out leg, and answers one asker for one burn, at most this often: the payout
/// poll, the cadence at which a proposal it could not judge is offered again.
pub const LEG_SHARE_EVERY_MS: u64 = PAYOUT_POLL_MS;
/// The cash-outs a custodian asks for at once: the burns the payout proposals it could not judge named, oldest
/// first; further ones are asked for as these are answered or paid.
pub const LEG_WANT_MAX: usize = 16;
/// The widest `LegProof` an answer carries: the signatures and envelopes of a vault (about 80 KB at sixteen
/// custodians), or of the whole bonded set on a chain that has not cut its custody yet (about 9 KB a custodian).
pub const LEG_SHARE_PROOF_MAX: usize = 1 << 20;

/// ⭐ OWED, THE HAND-OVER (2026-11-11) — A CASH-OUT'S LEG IS HANDED TO A CUSTODIAN THAT ADOPTED AFTER ITS BLOCK LEFT EVERY
/// BODY WINDOW (`WireMsg::LegShare`, carried in the hand-over lanes' signed envelope,
/// `node::opening_share::SignedShare`). A payout needs two thirds of the paying vault to
/// hold their legs; a custodian that joined by a certified state after the burn applied holds an owed release in its
/// ledger and no leg (lane owed re-opens it from the block while a body window still holds the block; past that nothing
/// on the chain carries it). So such a custodian ASKS its vault for the burn a payout proposal just named, and ONE
/// custodian per ask (the next seat after the asker each round) answers with the object's signed parts
/// (`peg_out_tx::LegProof`), which every custodian that booked the cash-out keeps until the release is paid.
/// THE ASKER BELIEVES NOTHING: `Node::recover_peg_out_leg_signed` runs the custody quorum's own tally over the parts,
/// against its own validator set and its own ledger's owed set, and opens only the envelope sealed to itself.
/// PRIVACY: an ask names a nullifier the payout proposal it answers already named on the same mesh; the answer is the
/// public half of an object a block carried — no destination, amount or leg in the clear.
/// The door checklist is on `Node::recover_peg_out_leg_signed`; the RELAY's is on `node::opening_share::SignedShare`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegShare {
    /// The bonded custodian `from`, seated in vault `vault`, holds no leg for the owed burn `nullifier` (ask `round`).
    Ask { vault: u32, from: [u8; 32], nullifier: [u8; 32], round: u32 },
    /// The signed parts of the cash-out that burned `nullifier` (an encoded `peg_out_tx::LegProof`), for `to`.
    Give { to: [u8; 32], nullifier: [u8; 32], proof: Vec<u8> },
}

impl LegShare {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// `None` for anything that is not exactly one message of this lane within its bounds.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(b)?;
        match &m {
            LegShare::Give { proof, .. } if proof.is_empty() || proof.len() > LEG_SHARE_PROOF_MAX => None,
            _ => Some(m),
        }
    }
}

/// ⭐ §BR-5 — one cash-out piece this custodian owes but cannot read yet: the ticket (the destination under the ticket key),
/// its ONE epoch ciphertext (the ticket key encapsulated to the epoch key, §BR-9a step c), the signed ticketed commitment and
/// the leg's release and pay-after. It opens once two thirds of custody release the piece's epoch at its batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTicket {
    pub release_sats: u64,
    pub burn_height: u64,
    pub pay_after: u64,
    pub ticket: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: exactly `epoch_key::CT_BYTES` (the object's decode refused any other width).
    pub epoch_ct: Vec<u8>,
    pub redeem_commit: [u8; 32],
    /// FORMAT SLOT (§19.4 retired the custody-spent escrow of §BR-5 B5-d): always `None` now — kept so a persisted book (postcard,
    /// positional) still decodes; nothing writes or reads a value here.
    pub escrow: Option<EscrowPart>,
    /// §BR-5 B5-d — the escrow key (the epoch ciphertext's message `m`), once the piece's epoch opened while the escrow burn
    /// has not applied yet.
    pub key: Option<[u8; 32]>,
    /// The ticket key K, once the piece's epoch opened (kept so a burn that applies after the release still opens).
    pub opened: Option<[u8; 32]>,
    /// §BR-5 B5-d — when the key became known here (the executor rank's backoff runs from it), and when this custodian
    /// last asked for the escrow burn (0 = never).
    pub key_known_ms: u64,
    /// ⭐ §BR-4 B4-3 — a unit close's ladder pieces (empty for a cash-out piece): the opened ticket books one obligation per piece.
    pub pieces: Vec<u64>,
    pub burn_requested_ms: u64,
}

/// ⭐ §BR-5 B5-d — the escrow half of a pending ticket: the envelope sealed under the escrow key, this custodian's leg blind
/// and change clue, and the request's custodians (the executor's rank among them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowPart {
    pub envelope: Vec<u8>,
    pub leg_blind: crate::spend_frontier::Digest4,
    pub change_clue: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (the request's envelope count).
    pub custodians: Vec<[u8; 32]>,
}


/// ⭐ §BR-9a step (c) — one custodian's RELEASE of an epoch at its batch (spec §19.3, §19.4): its captured seed shares of
/// that epoch (`epoch_release::ReleaseBundle`), sealed to every other custodian's ML-KEM key — never public (§19.1 item 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochReleaseMsg {
    pub epoch: u64,
    pub from: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX envelopes (`decode` refuses wider), each one sealed bundle.
    pub sealed: Vec<([u8; 32], Vec<u8>)>,
}

/// One sealed bundle's widest form: an ML-KEM ciphertext, a tag and a bundle of one share per dealer (a postcard of at most
/// `PEG_ATTEST_SEALED_MAX` (dealer, share) pairs plus its header).
fn release_sealed_max() -> usize {
    crate::pqkem::ciphertext_len() + 16 + 64 + crate::peg_attest::PEG_ATTEST_SEALED_MAX * (32 + 1 + crate::epoch_deal_tx::SHARE_BYTES + 2)
}

impl EpochReleaseMsg {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let m: Self = crate::chain_object::decode_exact(bytes)?;
        (!m.sealed.is_empty()
            && m.sealed.len() <= crate::peg_attest::PEG_ATTEST_SEALED_MAX
            && m.sealed.iter().all(|(_, b)| b.len() <= release_sealed_max()))
        .then_some(m)
    }
}

/// How often a custodian re-sends its release of an epoch while the release window (the epoch after it) is open: a
/// custodian that restarted, or missed a bundle, gathers again within this. Five payout polls, nothing tuned.
pub const EPOCH_RELEASE_RESEND_MS: u64 = 5 * PAYOUT_POLL_MS;

/// The book as it stood before the leg hand-over (no `leg_proofs`) — read so a book written before it still opens.
#[derive(Deserialize)]
struct CustodyBookV5 {
    obligations: BTreeMap<[u8; 32], Obligation>,
    locks: BTreeMap<[u8; 32], Lock>,
    addresses: BTreeMap<String, CoinAddress>,
    leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
    deposits: BTreeMap<String, DepositRec>,
    tickets: BTreeMap<[u8; 32], PendingTicket>,
    costs: BTreeMap<[u8; 32], Vec<u8>>,
}

/// The book as it stood before the cost lane (no `costs`) — read so a custodian's book written before stage three
/// still opens.
#[derive(Deserialize)]
struct CustodyBookV4 {
    obligations: BTreeMap<[u8; 32], Obligation>,
    locks: BTreeMap<[u8; 32], Lock>,
    addresses: BTreeMap<String, CoinAddress>,
    leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
    deposits: BTreeMap<String, DepositRec>,
    tickets: BTreeMap<[u8; 32], PendingTicket>,
}

/// The book as tickets stood under the per-ticket shares (before §BR-9a step c) — read so such a book still opens; its
/// share tickets cannot be opened by an epoch release, so they are dropped (their pieces stay in their owners' escrows).
#[derive(Deserialize)]
struct CustodyBookV3 {
    obligations: BTreeMap<[u8; 32], Obligation>,
    locks: BTreeMap<[u8; 32], Lock>,
    addresses: BTreeMap<String, CoinAddress>,
    leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
    deposits: BTreeMap<String, DepositRec>,
    #[allow(dead_code)]
    tickets: BTreeMap<[u8; 32], PendingTicketV3>,
}
#[derive(Deserialize)]
#[allow(dead_code)]
struct PendingTicketV3 {
    release_sats: u64,
    burn_height: u64,
    pay_after: u64,
    ticket: Vec<u8>,
    share_commits: Vec<[u8; 32]>,
    redeem_commit: [u8; 32],
    shares: BTreeMap<u8, Vec<u8>>,
    mine: Option<crate::shamir::Share>,
    released_ms: u64,
    escrow: Option<(Vec<u8>, crate::spend_frontier::Digest4, Vec<u8>, Vec<([u8; 32], Vec<u8>)>)>,
    key: Option<[u8; 32]>,
    key_known_ms: u64,
    pieces: Vec<u64>,
    burn_requested_ms: u64,
}

/// The book as it stood before §BR-5 (no `tickets`) — read so a custodian's book written before tickets still opens.
#[derive(Deserialize)]
struct CustodyBookV2 {
    obligations: BTreeMap<[u8; 32], Obligation>,
    locks: BTreeMap<[u8; 32], Lock>,
    addresses: BTreeMap<String, CoinAddress>,
    leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
    deposits: BTreeMap<String, DepositRec>,
}

/// The pre-§BR-2 book (no `deposits`) — read so a custodian's book written before co-signed deposits still opens.
#[derive(Deserialize)]
struct CustodyBookV1 {
    obligations: BTreeMap<[u8; 32], Obligation>,
    locks: BTreeMap<[u8; 32], Lock>,
    addresses: BTreeMap<String, CoinAddress>,
    leaves: BTreeMap<[u8; 32], Vec<([u8; 32], u128)>>,
}

/// §BR-2 — one minted co-signed deposit's sweep, as the block's sealed leg carried it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRec {
    pub depositor_x: [u8; 32],
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    pub fee_sats: u64,
    /// The depositor's BIP-340 signature (64 bytes) over the sweep leaf's sighash.
    pub sig: Vec<u8>,
}

/// One reserve coin a proposal spends, as the proposer saw it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    pub address: String,
}

/// The proposal every node relays and every custodian judges for itself. It names burns by nullifier only; each
/// signer supplies the destinations from ITS OWN sealed book, so no destination ever rides the mesh (DB-110).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutProposal {
    pub asset: String,
    pub epoch: u64,
    pub proposer: [u8; 32],
    pub legs: Vec<[u8; 32]>,
    pub inputs: Vec<PayoutInput>,
    pub fee_sats: u64,
    pub change_nonce: [u8; 32],
    /// ⭐ §BR-8 B8-a — the decoy legs `(validator id, sats)` the decoy rule gives this batch (every signer recomputes them).
    /// O1-FOOTPRINT-REVIEWED: bounded by BATCH_MAX.
    pub decoys: Vec<([u8; 32], u64)>,
    /// The fee rate the decoy rule priced decoys at (each signer bounds it by its own estimate, F7).
    pub fee_rate: u64,
}

impl PayoutProposal {
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }

    /// Bounded decode — a proposal wider than one payout transaction can carry is refused before anything reads it.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let p: Self = crate::chain_object::decode_exact(bytes)?;
        // A §BR-2 deposit sweep pays no legs: one input, no decoys, its output the deposit's sweep address. Refusing every
        // leg-less proposal here threw each sweep away before any custodian judged it, so no deposit was ever swept and no
        // cash-out was ever paid (MEASURED 2026-11-07, btc_bridge.py: 68 sweep proposals, 0 signatures, 0 BTC at the redeemer).
        // Whether the one input really is a co-signed deposit is `verify`'s judgement (`verify_sweep`); any other leg-less
        // proposal is refused there.
        // SAFE AT SCALE, stage three: a CONSOLIDATION pays no legs either — one to `PAYOUT_INPUTS_MAX` reserve coins from
        // under a vault's other keys to its current key's home address (`verify_consolidation`). No leg-less proposal
        // carries a decoy: decoys ride a batch of cash-outs.
        if (p.legs.is_empty() && !p.decoys.is_empty()) || p.legs.len() > BATCH_MAX || p.inputs.is_empty() || p.inputs.len() > PAYOUT_INPUTS_MAX || p.decoys.len() > BATCH_MAX {
            return None;
        }
        if p.asset.len() > 8 || p.inputs.iter().any(|i| i.address.len() > crate::peg_attest::PEG_ATTEST_ADDRESS_MAX) {
            return None;
        }
        Some(p)
    }

    /// The proposal's identity: a keyed hash of its one encoding, so a signature names exactly these bytes.
    pub fn id(&self) -> Option<[u8; 32]> {
        let mut h = blake3::Hasher::new_derive_key("MUSD/btc-payout/proposal/v1");
        h.update(&self.encode()?);
        Some(*h.finalize().as_bytes())
    }
}

/// One custodian's independent signatures over a proposal's inputs — 64 bytes per input it could sign, empty
/// for an input whose leaf does not hold its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutSig {
    pub proposal_id: [u8; 32],
    pub signer: [u8; 32],
    pub sigs: Vec<Vec<u8>>,
}

impl PayoutSig {
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: Self = crate::chain_object::decode_exact(bytes)?;
        if s.sigs.is_empty() || s.sigs.len() > PAYOUT_INPUTS_MAX || s.sigs.iter().any(|x| !(x.is_empty() || x.len() == 64)) {
            return None;
        }
        Some(s)
    }
}

/// What verifying a proposal against this node's own book, source and chain produced.
struct InputPlan {
    leaf: CustodyLeaf,
    control: Vec<u8>,
    sighash: [u8; 32],
    /// §BR-2: on a deposit sweep, the depositor's signature — the sweep leaf's `CHECKSIGVERIFY` pops it first.
    depositor_sig: Option<[u8; 64]>,
}

struct Plan {
    tx: Payout,
    inputs: Vec<InputPlan>,
    legs_sats: u64,
    /// §BR-8: the batch's decoy legs as paid (with their output index) and their fee in USDm atomic.
    decoys: Vec<crate::decoy_tx::DecoyEntry>,
    decoy_fee_usdm: u64,
    /// The change coin this payout creates, if any: `(address, nonce, leaf hash)` — a reserve coin to book.
    change: Option<(String, [u8; 32], [u8; 32])>,
    /// spec §3g.1: a rebalance move's first output `(sats, script)` — the part leaving for the receiving vault; `None` for
    /// every other payout. Carried into the move's cost evidence (`CostEvidence::rebalance_out`).
    /// CACHE-ONLY: this custodian's own plan of a transaction it judged; the ledger moves only by the `Class::ReserveCost`
    /// and `Class::VaultRebalance` objects blocks carry.
    rebalance_out: Option<(u64, Vec<u8>)>,
}

struct Slot {
    proposal: PayoutProposal,
    plan: Plan,
    sigs: BTreeMap<[u8; 32], Vec<Option<[u8; 64]>>>,
    txid_display: Option<String>,
    raw_hex: Option<String>,
    /// how many times this slot was re-offered, and when it is offered next (`resend_unfinished`'s backoff)
    resent: u32,
    next_resend_ms: u64,
}

/// The longest a slot waits between re-offers: `PAYOUT_POLL_MS` doubled per re-offer up to 2^6 (about 11 minutes).
const RESEND_BACKOFF_MAX_SHIFT: u32 = 6;

/// The lane: the book, the proposals in flight, the burns owed on another chain awaiting their own lane (drained
/// every tick), and the poll clock.
pub struct PayoutLane {
    book: CustodyBook,
    book_path: PathBuf,
    slots: BTreeMap<[u8; 32], Slot>,
    foreign: Vec<([u8; 32], Obligation)>,
    last_poll_ms: u64,
    no_source_said: bool,
    /// ⭐ F347c — the proposals this node relayed WITHOUT judging them (it holds no custodian key, or no source to
    /// judge against). Every `fresh` answer must be backed by a record, or a copy coming back through the relay is
    /// fresh again and the proposal circulates for ever. MEASURED on real processes ([slotF347c], five nodes): once
    /// the burn settled, every custodian refused the proposal ("not an owed burn") and RE-RELAYED it; node3 shed
    /// 68,405 Payout cells after the settlement against 11 before it (F347b logged the same loop as ~6,000 refusals
    /// per node). Oldest-first at `PAYOUT_SLOTS_MAX`, the proposals-in-flight bound: a copy arriving after its id
    /// left the ring is relayed once more, never in a loop.
    unjudged_relayed: std::collections::VecDeque<[u8; 32]>,
    /// ⭐ §BR-9a step (c) — the release bundles this custodian has opened, per epoch (its own included). PROCESS-LOCAL by
    /// design: they hold seed shares, are re-sent by every custodian every `EPOCH_RELEASE_RESEND_MS` while the epoch's release
    /// window is open, and are erased with the epoch (§19 item 6). O1-INFINITY-REVIEWED: at most the epochs whose round the
    /// ledger still holds (≤ 3), one bundle per roster member each.
    epoch_bundles: BTreeMap<u64, Vec<crate::epoch_release::ReleaseBundle>>,
    /// The epochs opened here: their key pair (process-local; erased two epochs after the epoch, §19 item 6).
    /// O1-INFINITY-REVIEWED: at most 3 epochs.
    epoch_secrets: BTreeMap<u64, (crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey)>,
    /// When this custodian last sent its release of each epoch (the re-send clock). O1-INFINITY-REVIEWED: ≤ 3 epochs.
    release_sent_ms: BTreeMap<u64, u64>,
    /// The epochs whose dealer faults this node has already handed to the runtime to publish. O1-INFINITY-REVIEWED: ≤ 3.
    faults_handed: std::collections::BTreeSet<u64>,
    /// OWED — has this process read its block window for cash-out legs it owes yet (`Node::recover_cash_out_legs_from_window`)?
    /// A burn's leg reaches this lane as an event the node queues in RAM; a process that ended between the block's apply and
    /// this lane's next tick lost it, though the block is still in its window. Read once, the first tick this node holds custody.
    window_read: bool,
    /// ⭐ R3 — this node's own Bitcoin fee readings, one per `FEE_SAMPLE_MS`, the newest last: what "a low fee" is
    /// measured against (its own trailing median over a day). PROCESS-LOCAL by design: a restart reads "not low yet"
    /// until `FEE_RING_MIN` readings stand, and the re-key's deadline (`Node::vault_key_move_urgent`) never waits on it.
    /// O1-INFINITY-REVIEWED: at most `FEE_RING_LEN` readings (one day of minutes), 8 bytes each.
    fee_ring: std::collections::VecDeque<u64>,
    fee_ring_at_ms: u64,
    /// What the last complete scan of this book's addresses on this node's own source showed: the custody leaves
    /// (by hash) with a coin under them, and the total. `None` until every address answered once.
    /// CACHE-ONLY: this custodian's own view of Bitcoin; it decides only what THIS custodian signs.
    /// O1-INFINITY-REVIEWED: one hash per leaf the book holds.
    coin_scan: Option<(std::collections::BTreeSet<[u8; 32]>, u128)>,
    /// The coin-list lane's clocks: this custodian's ask number and when it last asked; whom it last answered and when.
    /// O1-INFINITY-REVIEWED: one entry per asker of this vault (sixteen at most), forgotten after `COIN_SHARE_EVERY_MS`.
    coin_ask: (u32, u64),
    coin_gave: BTreeMap<[u8; 32], u64>,
    /// ⭐ OWED, the hand-over (`LegShare`) — the owed burns a payout named that this custodian holds no leg for, each
    /// with its ask number and when it was last asked; and whom this custodian answered for which burn, and when.
    /// PROCESS-LOCAL by design: a restart forgets what it wanted and the next payout proposal names it again.
    /// O1-INFINITY-REVIEWED: `leg_want` at most `LEG_WANT_MAX`; `leg_gave` one entry per (asker, burn) answered in
    /// the last `LEG_SHARE_EVERY_MS` (a vault's custodians times the burns asked for).
    leg_want: BTreeMap<[u8; 32], (u32, u64)>,
    leg_gave: BTreeMap<([u8; 32], [u8; 32]), u64>,
    /// This node's own x-only custody point, derived once from the key file (`refresh_own_point`), and whether and
    /// when that was last tried. The PUBLIC half of its Bitcoin custody key: nothing secret is kept here.
    own_point: Option<[u8; 32]>,
    own_point_tried: bool,
    own_point_tried_ms: u64,
    /// spec §3g.1: the rebalance parts (by their leg id) this custodian's own source showed arrived under its vault's
    /// consented key at its last poll (`check_rebalance_arrivals`). PROCESS-LOCAL by design: re-read every poll.
    /// O1-INFINITY-REVIEWED: one entry per part FOR this vault — at most one (the carve door).
    rebalance_seen: std::collections::BTreeSet<[u8; 32]>,
}

#[cfg(test)]
thread_local! {
    /// TESTS ONLY — the Bitcoin custody secret the lanes on this thread sign with (`PayoutLane::own_secret`): a pin
    /// switches it to act as one fixture custodian, then another.
    pub(crate) static TEST_BRIDGE_SECRET: std::cell::Cell<Option<[u8; 32]>> = const { std::cell::Cell::new(None) };
}

/// One fee reading a minute, a day of them, and the fewest a "low fee" judgement stands on (six minutes).
pub const FEE_SAMPLE_MS: u64 = 60_000;
pub const FEE_RING_LEN: usize = 24 * 60;
pub const FEE_RING_MIN: usize = 6;

fn book_path() -> PathBuf {
    // DB-341: a per-node file lives in the node's state directory under the port this process SERVES — an isolated
    // node (MONEROUSD_STATE_DIR) never reads or writes the operator's live book.
    crate::persist::state_dir().join(format!("custody-book-{}.bin", crate::persist::serving_port()))
}

fn h32(display: &[u8; 32]) -> String {
    btc_tx::hex(&display[..8])
}

impl PayoutLane {
    /// Load the book this custodian keeps beside its validator key (an empty book when none exists yet).
    pub fn new() -> Self {
        let book_path = book_path();
        // Through the custody keystore: sealed at rest under the operator passphrase when one is configured.
        // O1-INFINITY-REVIEWED: this custodian's own book, one file whose size is set by the obligations still open
        // (settled ones leave it); the read existed before and only the at-rest form changes.
        let book = match crate::keystore::read_key_file(&book_path) {
            Ok(bytes) => match crate::chain_object::decode_exact::<CustodyBook>(&bytes)
                .or_else(|| {
                    crate::chain_object::decode_exact::<CustodyBookV5>(&bytes).map(|v| CustodyBook {
                        obligations: v.obligations,
                        locks: v.locks,
                        addresses: v.addresses,
                        leaves: v.leaves,
                        deposits: v.deposits,
                        tickets: v.tickets,
                        costs: v.costs,
                        leg_proofs: BTreeMap::new(),
                    })
                })
                .or_else(|| {
                    crate::chain_object::decode_exact::<CustodyBookV4>(&bytes).map(|v| CustodyBook {
                        obligations: v.obligations,
                        locks: v.locks,
                        addresses: v.addresses,
                        leaves: v.leaves,
                        deposits: v.deposits,
                        tickets: v.tickets,
                        costs: BTreeMap::new(),
                        leg_proofs: BTreeMap::new(),
                    })
                })
                .or_else(|| {
                    crate::chain_object::decode_exact::<CustodyBookV3>(&bytes).map(|v| CustodyBook {
                        obligations: v.obligations,
                        locks: v.locks,
                        addresses: v.addresses,
                        leaves: v.leaves,
                        deposits: v.deposits,
                        tickets: BTreeMap::new(),
                        costs: BTreeMap::new(),
                        leg_proofs: BTreeMap::new(),
                    })
                })
                .or_else(|| {
                    crate::chain_object::decode_exact::<CustodyBookV2>(&bytes).map(|v| CustodyBook {
                        obligations: v.obligations,
                        locks: v.locks,
                        addresses: v.addresses,
                        leaves: v.leaves,
                        deposits: v.deposits,
                        tickets: BTreeMap::new(),
                        costs: BTreeMap::new(),
                        leg_proofs: BTreeMap::new(),
                    })
                })
                .or_else(|| {
                    crate::chain_object::decode_exact::<CustodyBookV1>(&bytes).map(|v| CustodyBook {
                        obligations: v.obligations,
                        locks: v.locks,
                        addresses: v.addresses,
                        leaves: v.leaves,
                        deposits: BTreeMap::new(),
                        tickets: BTreeMap::new(),
                        costs: BTreeMap::new(),
                        leg_proofs: BTreeMap::new(),
                    })
                }) {
                Some(b) => b,
                None => {
                    eprintln!("[btc-payout] ⛔ the custody book on disk does not decode — starting from an empty book; obligations re-appear as this node re-applies its blocks");
                    CustodyBook::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CustodyBook::default(),
            Err(e) => {
                eprintln!("[btc-payout] ⛔ the custody book on disk does not open ({e}) — starting from an empty book; obligations re-appear as this node re-applies its blocks");
                CustodyBook::default()
            }
        };
        PayoutLane {
            book,
            book_path,
            slots: BTreeMap::new(),
            foreign: Vec::new(),
            last_poll_ms: 0,
            no_source_said: false,
            unjudged_relayed: std::collections::VecDeque::new(),
            epoch_bundles: BTreeMap::new(),
            epoch_secrets: BTreeMap::new(),
            release_sent_ms: BTreeMap::new(),
            faults_handed: std::collections::BTreeSet::new(),
            window_read: false,
            fee_ring: std::collections::VecDeque::new(),
            fee_ring_at_ms: 0,
            coin_scan: None,
            coin_ask: (0, 0),
            coin_gave: BTreeMap::new(),
            leg_want: BTreeMap::new(),
            leg_gave: BTreeMap::new(),
            own_point: None,
            own_point_tried: false,
            own_point_tried_ms: 0,
            rebalance_seen: std::collections::BTreeSet::new(),
        }
    }

    /// Relay-once for a proposal this node cannot judge: `true` exactly the first time `id` is seen here (F347c).
    fn first_unjudged_sight(&mut self, id: &[u8; 32]) -> bool {
        if self.unjudged_relayed.contains(id) {
            return false;
        }
        if self.unjudged_relayed.len() >= PAYOUT_SLOTS_MAX {
            self.unjudged_relayed.pop_front();
        }
        self.unjudged_relayed.push_back(*id);
        true
    }

    pub fn book(&self) -> &CustodyBook {
        &self.book
    }

    /// DB-121x: the burns this lane opened from blocks whose destination is on another chain — the runtime hands
    /// them to that chain's lane. Drained on every call.
    pub fn take_foreign_obligations(&mut self) -> Vec<([u8; 32], Obligation)> {
        std::mem::take(&mut self.foreign)
    }

    /// How many proposals this node is tracking (the journeys read it).
    pub fn proposals_in_flight(&self) -> usize {
        self.slots.len()
    }

    /// Through the custody keystore (atomic: a temp name renamed into place; sealed when a passphrase is configured).
    fn save(&self) {
        match postcard::to_allocvec(&self.book) {
            Ok(bytes) => {
                if let Err(e) = crate::keystore::write_key_file(&self.book_path, &bytes) {
                    eprintln!("[btc-payout] ⛔ the custody book did not persist: {e}");
                }
            }
            Err(e) => eprintln!("[btc-payout] ⛔ the custody book did not encode: {e}"),
        }
    }

    fn leaf_of(members: &[([u8; 32], u128)]) -> Option<CustodyLeaf> {
        btc_tx::custody_leaf(members)
    }

    /// Record a minted deposit's coin address under the leaf that derives it — the live set's or one this book
    /// already holds — so the lane can spend it later. A coin no known leaf derives is named loudly: nothing in
    /// this lane can sign for it.
    fn record_coin(&mut self, node: &Node, address: &str, d_blind: &Digest4, sweep: Option<&crate::peg_attest::SweepAuth>) {
        let nonce = crate::spend_frontier::digest_to_lane_bytes(d_blind).to_vec();
        let hrp = crate::bridge::btc_net().hrp();
        let want = address.trim();
        let current = node.custody_members_current();
        let mut candidates: Vec<Vec<([u8; 32], u128)>> = Vec::new();
        // SAFE AT SCALE, stage three: the keys the chain records for this custodian's vault come first — a deposit is
        // minted to the current key's address or to a replaced key's inside its window (`Node::vault_keys_mintable`),
        // and a custodian that joined after a key was taken still books a deposit paid to it
        for k in node.peg().vault_keys(node.vault_here()) {
            candidates.push(k.btc.members.clone());
        }
        if !current.is_empty() {
            candidates.push(current);
        }
        for members in self.book.leaves.values() {
            candidates.push(members.clone());
        }
        for members in candidates {
            let Some(leaf) = Self::leaf_of(&members) else {
                continue;
            };
            // §BR-2: a co-signed deposit derives as the two-leaf output over (leaf, D, nonce); it is booked WITH its sweep
            let derived_x = match sweep {
                Some(a) => btc_tx::deposit_output(&leaf, &a.depositor_x, &nonce).map(|o| o.output_x),
                None => btc_tx::reserve_output(&leaf, &nonce).map(|o| o.output_x),
            };
            let Some(out_x) = derived_x else {
                continue;
            };
            if btc_tx::reserve_address(hrp, &out_x) == want {
                self.book.leaves.entry(leaf.leaf_hash).or_insert(members);
                self.book.addresses.insert(want.to_string(), CoinAddress { nonce, leaf_hash: leaf.leaf_hash });
                if let Some(a) = sweep {
                    self.book.deposits.insert(
                        want.to_string(),
                        DepositRec {
                            depositor_x: a.depositor_x,
                            txid: a.txid,
                            vout: a.vout,
                            value_sats: a.value_sats,
                            fee_sats: a.fee_sats,
                            sig: a.sig.to_vec(),
                        },
                    );
                }
                self.save();
                return;
            }
        }
        eprintln!("[btc-payout] ⛔ a minted deposit's reserve address derives under NO custody leaf this node knows — the coin cannot be spent by this lane until the set that issued it is known");
    }

    /// This node's own Bitcoin custody secret: the validator key file's (`bridge::node_own_bridge_secret`). In a test
    /// build a pin may seat ONE thread as a fixture custodian (`TEST_BRIDGE_SECRET`), so two custodians' lanes can be
    /// driven in one process, each signing with its own key.
    fn own_secret() -> Option<[u8; 32]> {
        #[cfg(test)]
        if let Some(s) = TEST_BRIDGE_SECRET.with(std::cell::Cell::get) {
            return Some(s);
        }
        crate::bridge::node_own_bridge_secret()
    }

    /// This node's own x-only custody point (its Bitcoin signing key's PUBLIC half) — `None` on a node that holds none.
    /// ⛔ READ FROM THE LANE'S COPY, NEVER FROM THE KEY FILE ON THE TICK PATH. The secret is read through the custody
    /// keystore on each use (`bridge::node_own_bridge_secret`), and a keystore sealed under the operator's passphrase
    /// pays a key derivation per read. 7217023e called that from `absorb`, which runs on every runtime loop: on a
    /// sealed custodian that is a key derivation per loop (found reading the code 2026-11-11, before any sealed node
    /// ran it). The public point is derived once (`refresh_own_point`, at most one try per poll) and kept here.
    fn own_point(&self) -> Option<[u8; 32]> {
        #[cfg(test)]
        if let Some(s) = TEST_BRIDGE_SECRET.with(std::cell::Cell::get) {
            return btc_tx::xonly_pubkey(&s);
        }
        self.own_point
    }

    /// Derive this node's custody point once: tried at most once per poll until the key file answers.
    fn refresh_own_point(&mut self, now_ms: u64) {
        if self.own_point.is_some() || (self.own_point_tried && now_ms.saturating_sub(self.own_point_tried_ms) < PAYOUT_POLL_MS) {
            return;
        }
        (self.own_point_tried, self.own_point_tried_ms) = (true, now_ms);
        self.own_point = Self::own_secret().and_then(|s| btc_tx::xonly_pubkey(&s));
    }

    /// ⭐ SAFE AT SCALE, stage three — IS THIS NODE STILL A KEY HOLDER? Its custody point sits in the Bitcoin leaf of a
    /// key the chain still records alive, though the chain no longer seats it (it left, or was moved to another
    /// vault). Such a node judges and signs ONE thing: the move of that key's coins to its old vault's current key —
    /// the act that lets the vault retire the key and the chain return its collateral (`PegLedger::vault_key_holds`).
    /// It proposes no payout, signs no cash-out, opens no envelope: the seat predicate (`Node::custodian_id`) still
    /// gates every other custodian act. CACHE-ONLY: read from the chain's key record.
    fn key_holder(&self, node: &Node) -> bool {
        self.own_point().is_some_and(|x| !node.vault_keys_holding_point(&x).is_empty())
    }

    /// ⭐ R3 — BOOK THE HOME ADDRESS AND THE LEAF OF EVERY ALIVE KEY THAT HOLDS THIS NODE'S POINT, from the chain's key
    /// record alone (`Node::vault_key_home_btc`). A consolidation pays to the current key's home and a payout's change
    /// returns there, so this is how a custodian finds its vault's coins after a restart, a lost book, or a move it
    /// never saw gossiped: the record names the address, its own source shows the coins.
    /// O1-INFINITY-REVIEWED: at most `VAULT_KEYS_ALIVE_MAX` homes per vault this point is named in; a retired key's
    /// empty home leaves the book at the next scan (`scan_coins`).
    fn book_key_homes(&mut self, node: &Node) {
        let Some(x) = self.own_point() else { return };
        let mut changed = false;
        for (_, k) in node.vault_keys_holding_point(&x) {
            let Some((leaf, nonce, address)) = Node::vault_key_home_btc(k) else { continue };
            if !self.book.leaves.contains_key(&leaf.leaf_hash) {
                self.book.leaves.insert(leaf.leaf_hash, k.btc.members.clone());
                changed = true;
            }
            if !self.book.addresses.contains_key(&address) {
                self.book.addresses.insert(address, CoinAddress { nonce: nonce.to_vec(), leaf_hash: leaf.leaf_hash });
                changed = true;
            }
        }
        if changed {
            self.save();
        }
    }

    /// Take in what the blocks applied since the last tick taught this custodian, and remember the live leaf.
    pub fn absorb(&mut self, node: &mut Node) {
        node.remember_custody_leaf();
        let current = node.custody_members_current();
        if !current.is_empty() {
            if let Some(leaf) = Self::leaf_of(&current) {
                if !self.book.leaves.contains_key(&leaf.leaf_hash) {
                    self.book.leaves.insert(leaf.leaf_hash, current);
                    self.save();
                }
            }
        }
        self.book_key_homes(node);
        if !self.window_read && node.bonded_custodian_identity().is_some() {
            self.window_read = true;
            let _ = node.recover_cash_out_legs_from_window();
        }
        for ev in node.drain_payout_events() {
            match ev {
                PayoutEvent::Obligation { usdm_nullifier, release_sats, redeem_to, burn_height, pay_after } => {
                    if node.peg().release_pending(&usdm_nullifier) && release_sats > 0 {
                        // DB-121x: a burn owed in Monero is the Monero lane's; it is handed across untouched
                        // (`take_foreign_obligations`), never booked here where nothing could pay it.
                        if crate::bridge::is_monero_address(&redeem_to) {
                            self.foreign.push((usdm_nullifier, Obligation { release_sats, redeem_to, burn_height, pay_after }));
                            continue;
                        }
                        self.book
                            .obligations
                            .entry(usdm_nullifier)
                            .or_insert(Obligation { release_sats, redeem_to, burn_height, pay_after });
                        self.save();
                        // DB-375: the burn's nullifier is NOT logged — beside the payout amount it links a USDm spend to an
                        // external payout (digital cash: no cleartext nullifier in any log).
                        // CHAIN-OBJECT: unchanged by this edit — the obligation is booked from the burn the block carries,
                        // exactly as before; only a value is removed from a LOG line.
                        eprintln!("[btc-payout] obligation booked ({} sats, height {})", release_sats, burn_height);
                    }
                }
                PayoutEvent::ReserveCoin { address, d_blind, sweep } => {
                    self.record_coin(node, &address, &d_blind, sweep.as_ref());
                }
                PayoutEvent::Ticket { usdm_nullifier, release_sats, burn_height, pay_after, ticket, epoch_ct, redeem_commit, pieces, proof } => {
                    if !(node.peg().release_pending(&usdm_nullifier) && release_sats > 0) {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line; no nullifier, amount or destination.
                        eprintln!("[btc-payout] ⛔ a cash-out ticket arrived for a release this node's chain does not show pending — not held");
                    }
                    if node.peg().release_pending(&usdm_nullifier) && release_sats > 0 {
                        // OWED, the hand-over: the object's signed parts stay beside the leg until the release is paid
                        // CHAIN-OBJECT: Class::PegOut — a copy of public parts of the object this event was opened from.
                        if !proof.is_empty() && proof.len() <= LEG_SHARE_PROOF_MAX {
                            self.book.leg_proofs.entry(usdm_nullifier).or_insert(proof);
                        }
                        self.leg_want.remove(&usdm_nullifier);
                        self.book.tickets.entry(usdm_nullifier).or_insert(PendingTicket {
                            release_sats,
                            burn_height,
                            pay_after,
                            ticket,
                            epoch_ct,
                            redeem_commit,
                            escrow: None,
                            key: None,
                            opened: None,
                            key_known_ms: 0,
                            burn_requested_ms: 0,
                            pieces,
                        });
                        self.try_open_ticket(&usdm_nullifier);
                        self.save();
                    }
                }
            }
        }
    }

    /// ⭐ §BR-5 / §BR-9a step (c) — open ticket `nf` once its epoch is open here: decapsulate its ONE ciphertext under each
    /// epoch secret held (the FO check refuses every other epoch's), open the ticket against the signed ticketed commitment,
    /// and book the obligation (a Monero destination is handed to the Monero lane). A ticket no held epoch opens stays pending.
    fn try_open_ticket(&mut self, nf: &[u8; 32]) {
        let Some(t) = self.book.tickets.get(nf) else { return };
        let found = match t.opened {
            Some(k) => Some(k),
            None => self.epoch_secrets.values().find_map(|(pk, sk)| crate::epoch_key::decapsulate_message(pk, sk, &t.epoch_ct)).map(|(_, k)| k),
        };
        let Some(key) = found else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: public counts only.
            eprintln!(
                "[btc-payout] a cash-out ticket waits: none of the {} epoch key(s) open here decapsulates it (its epoch is not open on this node yet)",
                self.epoch_secrets.len()
            );
            return;
        };
        let commits = crate::cashout_ticket::ct_commits(&t.epoch_ct);
        let Some((address, pay_after, _blind)) = crate::cashout_ticket::open_ticketed(&key, &t.ticket, &commits, &t.redeem_commit) else {
            eprintln!("[btc-payout] ⛔ a ticket does not open its signed commitment under its epoch's key — it stays pending");
            return;
        };
        let Ok(redeem_to) = String::from_utf8(address) else { return };
        // ⭐ §BR-4 B4-3: a unit close's ticket books one obligation per ladder piece, each under its own key (the chain holds every
        // piece's key as an owed release), so the pieces join the ordinary per-denomination batches like any cash-out's
        if !t.pieces.is_empty() {
            let (pieces, burn_height, after) = (t.pieces.clone(), t.burn_height, pay_after.max(t.pay_after));
            self.book.tickets.remove(nf);
            for (i, sats) in pieces.into_iter().enumerate() {
                let ob = Obligation { release_sats: sats, redeem_to: redeem_to.clone(), burn_height, pay_after: after };
                let key = crate::unit_close_tx::piece_key(nf, i);
                if crate::bridge::is_monero_address(&ob.redeem_to) {
                    self.foreign.push((key, ob));
                } else {
                    self.book.obligations.entry(key).or_insert(ob);
                }
            }
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line — no nullifier, amount or destination.
            eprintln!("[btc-payout] a unit close's ticket opened at its epoch's release — its pieces are booked");
            return;
        }
        let ob = Obligation { release_sats: t.release_sats, redeem_to, burn_height: t.burn_height, pay_after: pay_after.max(t.pay_after) };
        self.book.tickets.remove(nf);
        if crate::bridge::is_monero_address(&ob.redeem_to) {
            self.foreign.push((*nf, ob));
        } else {
            self.book.obligations.entry(*nf).or_insert(ob);
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line — no nullifier, amount or destination.
        eprintln!("[btc-payout] a cash-out ticket opened at its epoch's release — its obligation is booked");
    }

    /// ⭐ §BR-9a step (c) — RELEASE this custodian's captured shares of every epoch whose batch has come (the fold stands in
    /// the epoch after it, `EpochKeyLedger::release_key`), sealed to every other custodian on the epoch's roster; re-sent every
    /// `EPOCH_RELEASE_RESEND_MS` while that window is open. Its own bundle joins its gathering at once. Also erases what this
    /// lane holds of an epoch whose round the ledger no longer keeps (§19 item 6).
    /// §BR-15 — the key pair of `epoch` this custodian holds (released, not yet erased): the DeFi lane opens an order's epoch
    /// layer with it.
    #[must_use]
    pub fn epoch_secret(&self, epoch: u64) -> Option<(crate::epoch_key::EpochPublicKey, crate::epoch_key::EpochSecretKey)> {
        self.epoch_secrets.get(&epoch).cloned()
    }

    fn release_epochs(&mut self, node: &Node, now_ms: u64) -> Vec<WireMsg> {
        let ledger = node.peg().epoch_keys();
        let held: std::collections::BTreeSet<u64> = ledger.epochs.keys().copied().collect();
        self.epoch_bundles.retain(|e, _| held.contains(e));
        self.epoch_secrets.retain(|e, _| held.contains(e));
        self.release_sent_ms.retain(|e, _| held.contains(e));
        self.faults_handed.retain(|e| held.contains(e));
        let Some(me) = node.custodian_id() else { return Vec::new() };
        let Some(e) = ledger.release_epoch() else { return Vec::new() };
        let (Some(_), Some(round)) = (ledger.release_key(e), ledger.epochs.get(&e)) else { return Vec::new() };
        let Some(mine) = node.epoch_seed_shares().get(&e) else { return Vec::new() };
        let bundle = crate::epoch_release::ReleaseBundle { from: me, epoch: e, shares: mine.iter().map(|(d, s)| (*d, s.clone())).collect() };
        let gathered = self.epoch_bundles.entry(e).or_default();
        if !gathered.iter().any(|b| b.from == me) {
            gathered.push(bundle.clone());
        }
        if self.release_sent_ms.get(&e).is_some_and(|t| now_ms.saturating_sub(*t) < EPOCH_RELEASE_RESEND_MS) {
            return Vec::new();
        }
        // to the epoch's roster AND every custodian bonded now: a round is dealt up to `DEAL_LEAD_EPOCHS` ahead to the custody
        // set of that moment, so a custodian who bonded since is on no roster of the lead, yet it signs every payout and must
        // open the tickets its batches pay (MEASURED 2026-11-08, real nodes: epoch 1's roster held only the first custodian,
        // the second never opened epoch 1, never booked the cash-out's obligation, and the 2-of-2 payout was never signed).
        // Opening still takes two thirds of the epoch's own roster (`epoch_release::open_epoch`); this only widens who receives.
        let mut to: Vec<[u8; 32]> = round.roster.iter().copied().chain(node.validators().bonded_custodian_eks().into_iter().map(|(id, _)| id)).collect();
        to.sort_unstable();
        to.dedup();
        let sealed: Vec<([u8; 32], Vec<u8>)> = to
            .iter()
            .filter(|id| **id != me)
            .filter_map(|id| node.validators().registered_kem_ek(id).map(|ek| (*id, ek)))
            .filter_map(|(id, ek)| crate::epoch_release::seal_bundle(&ek, &bundle).map(|b| (id, b)))
            .collect();
        self.release_sent_ms.insert(e, now_ms.max(1));
        if sealed.is_empty() {
            return Vec::new();
        }
        vec![WireMsg::EpochRelease(EpochReleaseMsg { epoch: e, from: me, sealed }.encode())]
    }

    /// ⭐ §BR-9a step (c) — try to OPEN epoch `e` from the bundles gathered here (`epoch_release::open_epoch`): on success its
    /// key pair is held and every pending ticket is tried; a convicted dealer's proofs are returned once for the runtime to
    /// publish (`Node::publish_epoch_fraud`); short = wait for more bundles.
    fn try_open_epoch(&mut self, node: &Node, e: u64) -> Vec<crate::epoch_release::FraudProof> {
        if self.epoch_secrets.contains_key(&e) {
            return Vec::new();
        }
        let ledger = node.peg().epoch_keys();
        let (Some(pk), Some(round)) = (ledger.release_key(e), ledger.epochs.get(&e)) else { return Vec::new() };
        let Some(bundles) = self.epoch_bundles.get(&e) else { return Vec::new() };
        match crate::epoch_release::open_epoch(e, round, &pk, bundles) {
            crate::epoch_release::EpochOpen::Key(sk) => {
                self.epoch_secrets.insert(e, (pk, sk));
                let pending: Vec<[u8; 32]> = self.book.tickets.iter().filter(|(_, t)| t.opened.is_none()).map(|(nf, _)| *nf).collect();
                for nf in pending {
                    self.try_open_ticket(&nf);
                }
                self.save();
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line and the public epoch number — no ticket, amount or destination.
                eprintln!("[btc-payout] epoch {e} is open at two thirds of custody — its tickets open");
                Vec::new()
            }
            crate::epoch_release::EpochOpen::Short => Vec::new(),
            crate::epoch_release::EpochOpen::Faulty(proofs) => {
                if self.faults_handed.insert(e) {
                    eprintln!("[btc-payout] ⛔ epoch {e}'s key does not rebuild — {} dealer(s) convicted; their fraud proofs go to the chain", proofs.len());
                    proofs
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// ⭐ §BR-9a step (c) — a custodian's epoch release arrived: every node relays it once; a custodian opens the bundle sealed
    /// to it, keeps it (one per sender) and tries to open the epoch. Returns (relay?, dealer faults to publish).
    pub fn on_epoch_release(&mut self, bytes: &[u8], node: &Node) -> (bool, Vec<crate::epoch_release::FraudProof>) {
        let Some(m) = EpochReleaseMsg::decode(bytes) else { return (false, Vec::new()) };
        if !self.first_unjudged_sight(blake3::hash(bytes).as_bytes()) {
            return (false, Vec::new());
        }
        let Some(b) = node.custodian_open_release(&m.sealed).filter(|b| b.from == m.from && b.epoch == m.epoch) else {
            return (true, Vec::new());
        };
        // only an epoch whose round the ledger keeps is gathered for (bounded: ≤ 3 epochs, one bundle per sender)
        if !node.peg().epoch_keys().epochs.contains_key(&m.epoch) {
            return (true, Vec::new());
        }
        let gathered = self.epoch_bundles.entry(m.epoch).or_default();
        if !gathered.iter().any(|x| x.from == b.from) {
            gathered.push(b);
        }
        let faults = self.try_open_epoch(node, m.epoch);
        (true, faults)
    }

    /// Verify a proposal against THIS node's own book, own Bitcoin source and own chain. `None` = this custodian
    /// will not sign it (the reason is logged; the proposer re-broadcasts, and a proposal that becomes true later
    /// — a burn finalizing, a coin maturing — is judged again then).
    /// ⭐ §BR-2 (spec §14) — a SWEEP proposal is exactly the transaction the depositor signed: the one minted deposit coin
    /// (its outpoint, value and fee as the block's sealed leg carried them), no legs, its whole value less that fee to the
    /// custody's single-leaf reserve address under `sweep_nonce` and the deposit's own leaf. The deposit must be MINTED on
    /// this node's chain (custody never sweeps an unminted deposit — its refund leaf stays the depositor's). The plan's
    /// input carries the depositor's signature for the witness; the custodians sign the sweep leaf's sighash as usual.
    fn verify_sweep(&self, p: &PayoutProposal, node: &Node, src: &BtcSource) -> Option<Plan> {
        let refuse = |why: &str| {
            eprintln!("[btc-payout] ⛔ not signing the sweep (§BR-2): {why}");
            None::<Plan>
        };
        if !p.legs.is_empty() || p.inputs.len() != 1 {
            return refuse("a sweep pays no legs and spends one deposit");
        }
        let inp = &p.inputs[0];
        let (Some(rec), Some(coin)) = (self.book.deposits.get(&inp.address), self.book.addresses.get(&inp.address)) else {
            return refuse("the deposit is not in this custodian's book");
        };
        if inp.txid != rec.txid || inp.vout != rec.vout || inp.value_sats != rec.value_sats || p.fee_sats != rec.fee_sats {
            return refuse("the proposal's coin or fee is not the one the depositor signed");
        }
        if p.change_nonce != btc_tx::sweep_nonce(&coin.nonce) {
            return refuse("the proposal's output is not the deposit's sweep address");
        }
        if !node.peg().deposit_minted(&crate::peg::deposit_id_for_reserve_address(&inp.address)) {
            return refuse("the deposit is not minted on this node's chain — custody never sweeps an unminted deposit");
        }
        // DB-185: every exit of this judgement names itself; a sweep refused by a silent `?` was re-proposed every tick for a
        // whole bridge run with no line saying which check held it (MEASURED 2026-11-07, btc_bridge.py: 68 proposals, 0 refusals).
        let members = match self.book.leaves.get(&coin.leaf_hash) {
            Some(m) => m,
            None => return refuse("the deposit's custody leaf is not in this custodian's book"),
        };
        let leaf = match Self::leaf_of(members) {
            Some(l) => l,
            None => return refuse("the deposit's custody leaf does not assemble from its members"),
        };
        if leaf.leaf_hash != coin.leaf_hash {
            return refuse("the assembled custody leaf is not the deposit's leaf");
        }
        let hrp = crate::bridge::btc_net().hrp();
        let out = match btc_tx::deposit_output(&leaf, &rec.depositor_x, &coin.nonce) {
            Some(o) => o,
            None => return refuse("the deposit output does not derive from its leaf, nonce and depositor key"),
        };
        if btc_tx::reserve_address(hrp, &out.output_x) != inp.address {
            return refuse("the deposit's address does not derive from its leaf, nonce and depositor key");
        }
        let display = btc_tx::txid_display_hex(&inp.txid);
        let Some((value, on_chain_spk)) = src.tx_out(&display, inp.vout) else {
            return refuse("this node's source does not show the deposit coin");
        };
        if value != rec.value_sats || on_chain_spk != btc_tx::p2tr_script_pubkey(&out.output_x) {
            return refuse("the deposit coin's value or script is not the signed one");
        }
        let coins = match src.utxos(&inp.address) {
            Some(c) => c,
            None => return refuse("this node's source does not list the deposit address's coins"),
        };
        let Some(c) = coins.iter().find(|c| c.txid == inp.txid && c.vout == inp.vout) else {
            return refuse("the deposit coin is not unspent on this node's source");
        };
        if !c.matured() {
            return refuse("the deposit coin has not matured yet");
        }
        let (tx, sweep_out) =
            match btc_tx::deposit_sweep_payout(&out, &leaf, &coin.nonce, rec.txid, rec.vout, rec.value_sats, rec.fee_sats) {
                Some(t) => t,
                None => return refuse("the sweep transaction does not build from the deposit"),
            };
        let sighash = match btc_tx::deposit_sweep_sighash(&tx, &out) {
            Some(h) => h,
            None => return refuse("the sweep's signature hash does not compute"),
        };
        let sig: [u8; 64] = match rec.sig.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return refuse("the depositor's sweep signature is not 64 bytes"),
        };
        if !btc_tx::verify_sighash_sig(&rec.depositor_x, &sighash, &sig) { // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own BIP-340 verify of the depositor's sweep signature (bridge endpoint)
            return refuse("the depositor's signature does not verify over the sweep");
        }
        let sweep_leaf = CustodyLeaf { slot_keys: leaf.slot_keys.clone(), k: leaf.k, script: out.sweep_leaf.clone(), leaf_hash: out.sweep_hash };
        let change = Some((btc_tx::reserve_address(hrp, &sweep_out.output_x), btc_tx::sweep_nonce(&coin.nonce), leaf.leaf_hash));
        Some(Plan {
            tx,
            inputs: vec![InputPlan { leaf: sweep_leaf, control: btc_tx::deposit_control_block(&out, true), sighash, depositor_sig: Some(sig) }],
            legs_sats: 0,
            decoys: Vec::new(),
            decoy_fee_usdm: 0,
            change,
            rebalance_out: None,
        })
    }

    /// The leaf a payout's change returns under and — once the chain records a key for this custodian's vault — the
    /// nonce it must carry (the key's home). Before any key is recorded: the live set's leaf and the proposal's own
    /// nonce, as it was.
    fn change_target(node: &Node) -> Option<(CustodyLeaf, Option<[u8; 32]>)> {
        let vault = node.vault_here();
        match node.peg().vault_key_current(vault) {
            Some(k) => Node::vault_key_home_btc(k).map(|(leaf, nonce, _)| (leaf, Some(nonce))),
            None => node.custody_leaf_current().map(|l| (l, None)),
        }
    }

    /// ⭐ R3 — IS THIS NODE'S OWN FEE READING LOW? At or under the trailing median of its own readings over the last
    /// day for a signer; at or under their lower quartile for the proposer (so a proposal made at one node's low
    /// reading is still low on its peers', whose readings differ a little). Never before `FEE_RING_MIN` readings stand.
    /// CACHE-ONLY: this node's own judgement of a foreign fee market; it decides only what THIS custodian signs.
    fn fee_is_low(&self, rate: u64, proposing: bool) -> bool {
        if self.fee_ring.len() < FEE_RING_MIN {
            return false;
        }
        let mut v: Vec<u64> = self.fee_ring.iter().copied().collect();
        v.sort_unstable();
        rate <= v[if proposing { v.len() / 4 } else { v.len() / 2 }]
    }

    /// The consolidation transaction, ONE spelling for the signer and for every judge of its fee: the proposal's
    /// inputs in the proposal's order (RBF sequence, as every payout), and the one output — everything they hold less
    /// the fee — at `home`. `None` when the inputs do not carry the fee and a dust-free output.
    fn consolidation_tx(p: &PayoutProposal, scripts: &[Vec<u8>], home_spk: Vec<u8>) -> Option<Payout> {
        let in_total = p.inputs.iter().try_fold(0u64, |a, i| a.checked_add(i.value_sats))?;
        let out_value = in_total.checked_sub(p.fee_sats).filter(|v| *v >= DUST_SATS)?;
        let inputs = p
            .inputs
            .iter()
            .zip(scripts)
            .map(|(i, spk)| TxIn { txid: i.txid, vout: i.vout, value_sats: i.value_sats, script_pubkey: spk.clone(), sequence: 0xffff_fffd })
            .collect();
        Some(Payout { inputs, outputs: vec![TxOut { value_sats: out_value, script_pubkey: home_spk }] })
    }

    /// A REBALANCE MOVE's transaction, ONE spelling for the signer and for every judge of its fee: the proposal's inputs in
    /// its order (RBF sequence), the part's output to the receiving vault, and the change — everything else less the fee — at
    /// this vault's home. `None` when the inputs do not carry the part, the fee and a dust-free change.
    fn rebalance_tx(p: &PayoutProposal, scripts: &[Vec<u8>], part_sats: u64, part_spk: Vec<u8>, home_spk: Vec<u8>) -> Option<Payout> {
        let in_total = p.inputs.iter().try_fold(0u64, |a, i| a.checked_add(i.value_sats))?;
        let change = in_total.checked_sub(part_sats)?.checked_sub(p.fee_sats).filter(|v| *v >= DUST_SATS)?;
        let inputs = p
            .inputs
            .iter()
            .zip(scripts)
            .map(|(i, spk)| TxIn { txid: i.txid, vout: i.vout, value_sats: i.value_sats, script_pubkey: spk.clone(), sequence: 0xffff_fffd })
            .collect();
        Some(Payout { inputs, outputs: vec![TxOut { value_sats: part_sats, script_pubkey: part_spk }, TxOut { value_sats: change, script_pubkey: home_spk }] })
    }

    /// ⭐ SAFE AT SCALE, stage three (spec §3g.1) — THE ONE LEG ID OF A REBALANCE'S BITCOIN MOVE out of vault `from`: derived
    /// from the slot's own coin seed, so a proposal names the part it moves (and nothing else: it is no burn), and this
    /// custodian's lock under it records that it signed a move of that part (`rebalance_signed`).
    #[must_use]
    pub fn rebalance_leg_id(node: &Node, from: u32) -> Option<[u8; 32]> {
        let seed = node.rebalance_coin_seed(from, "BTC")?;
        let mut h = blake3::Hasher::new_derive_key("musdm.btc.rebalance-leg.v1");
        h.update(&seed);
        Some(*h.finalize().as_bytes())
    }

    /// Where vault `from`'s part goes on Bitcoin: the leaf of the receiving vault's key `key` (rebuilt from the record's own
    /// inputs) under the slot's own coin seed — `(leaf, nonce, address)`, derived by both vaults from the chain alone.
    fn rebalance_target(node: &Node, from: u32, key: &crate::peg::VaultKeyRow) -> Option<(CustodyLeaf, [u8; 32], String)> {
        let leaf = btc_tx::custody_leaf(&key.btc.members).filter(|l| l.leaf_hash == key.btc.leaf)?;
        let nonce = node.rebalance_coin_seed(from, "BTC")?;
        let out = btc_tx::reserve_output(&leaf, &nonce)?;
        Some((leaf, nonce, btc_tx::reserve_address(crate::bridge::btc_net().hrp(), &out.output_x)))
    }

    /// The part's sats: the reserve of the part this custodian holds of vault `from`'s Bitcoin bridge leg (at least dust).
    fn rebalance_sats(node: &Node, from: u32) -> Option<u64> {
        let p = node.rebalance_part_held(from, crate::peg::NATIVE_PEG_ASSET_ID)?;
        u64::try_from(p.0).ok().filter(|v| *v >= DUST_SATS)
    }

    /// Has THIS custodian's own lane signed a Bitcoin move of vault `from`'s part? A custodian signs a part's move or its
    /// cancel, never both (`Node::own_rebalance_sigs`).
    #[must_use]
    pub fn rebalance_signed(&self, node: &Node, from: u32) -> bool {
        Self::rebalance_leg_id(node, from).is_some_and(|id| self.book.locks.contains_key(&id))
    }

    /// Did THIS custodian's own source show vault `from`'s part arrive under the key its vault consented to — one matured
    /// coin of exactly the part's sats at the address the slot derives? Read on the lane's own poll
    /// (`check_rebalance_arrivals`).
    #[must_use]
    pub fn rebalance_arrived(&self, node: &Node, from: u32) -> bool {
        Self::rebalance_leg_id(node, from).is_some_and(|id| self.rebalance_seen.contains(&id))
    }

    /// The poll's look for the parts FOR this custodian's vault: for each slot naming its vault with a Bitcoin leg, the
    /// consented key's address under the slot's seed on this node's own source. A coin found joins this book (its address,
    /// nonce and leaf), so the vault spends it like any reserve coin once the take has made its ledger count it.
    /// CACHE-ONLY: this custodian's own view of Bitcoin; it decides only what THIS custodian signs.
    fn check_rebalance_arrivals(&mut self, node: &Node, src: &BtcSource) {
        self.rebalance_seen.clear();
        if node.custodian_id().is_none() {
            return;
        }
        let here = node.vault_here();
        let incoming: Vec<u32> = node.peg().vault_parts_all().filter(|(_, p)| p.into == here && p.legs.iter().any(|l| l.asset == crate::peg::NATIVE_PEG_ASSET_ID)).map(|(f, _)| f).collect();
        for from in incoming {
            let (Some(key), Some(sats), Some(id)) = (node.rebalance_consented_key(from), Self::rebalance_sats(node, from), Self::rebalance_leg_id(node, from)) else { continue };
            let Some((leaf, nonce, address)) = Self::rebalance_target(node, from, &key) else { continue };
            let Some(coins) = src.utxos(&address) else { continue };
            if coins.iter().any(|c| c.value_sats == sats && c.matured()) {
                self.rebalance_seen.insert(id);
                if !self.book.addresses.contains_key(&address) {
                    self.book.leaves.entry(leaf.leaf_hash).or_insert_with(|| key.btc.members.clone());
                    self.book.addresses.insert(address, CoinAddress { nonce: nonce.to_vec(), leaf_hash: leaf.leaf_hash });
                    self.save();
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed line — custody's own move between its own vaults; no user, amount or address.
                    eprintln!("[btc-payout] a rebalance's part arrived under this vault's consented key — booked as a reserve coin");
                }
            }
        }
    }

    /// ⭐⭐ SAFE AT SCALE, stage three (spec §3g.1) — A REBALANCE'S BITCOIN MOVE: the part of this vault's ledger the chain has
    /// carved for another vault, paid in coins. One proposal leg, the part's id (`rebalance_leg_id`). A custodian signs it only
    /// when, on ITS OWN chain, book and source:
    ///   • its own vault has a part at rest with a Bitcoin leg, and two thirds of the receiving vault consented to a key the
    ///     chain records as that vault's CURRENT key (`Node::rebalance_send_key`);
    ///   • the first output is exactly the part's sats (its own opening of the part) at that key's leaf under the slot's seed,
    ///     and the second the whole rest less the fee at its own vault's current home — the proposal names no address;
    ///   • every input is a matured, unspent reserve coin of its own book under a key of its own vault (never a co-signed
    ///     deposit: that is swept first), at the stated value and script;
    ///   • the fee is inside F7 (at least 1 sat/vB, at most `FEE_CEIL_MULTIPLE` × its own estimate) and comes out of the
    ///     change, never the part; it is booked by `Class::ReserveCost` once confirmed.
    /// §9.6 (a proposal door): (1) no PoW — judged before any signature; (2) each signer's own derivation from its own
    /// book; (3) value — the part leaves for exactly where the receiving vault's quorum consented, the carve has already
    /// taken it out of this vault's ledger, the fee is F7-bounded and booked; (4) a replay spends coins that are gone, and
    /// this custodian's lock records the one move it signed for the part; (5) at most `PAYOUT_INPUTS_MAX` inputs, two source
    /// reads each; (6) parity with `verify_consolidation`: the same input checks and fee ceiling, an output derived from the
    /// chain's key record; (7) SCALE — one vault's signers, nothing per bonded node; (8) AI RESISTANT — (b) bounded by the
    /// vault's bonds: two thirds of a vault can always sign its coins away; a lying proposer or a persuasive message can
    /// move the part only to the key the receiving vault's own quorum named.
    /// cons: one Bitcoin transaction (and its fee, the bonders' debt) per part; a part under dust plus fee is not moved
    /// (its giver cancels it after the day).
    fn verify_rebalance_move(&self, p: &PayoutProposal, node: &Node, src: &BtcSource) -> Option<Plan> {
        let refuse = |why: &str| {
            eprintln!("[btc-payout] ⛔ not signing the rebalance move (§3g.1): {why}");
            None::<Plan>
        };
        node.custodian_id()?;
        let from = node.vault_here();
        if !p.decoys.is_empty() || p.inputs.is_empty() || Self::rebalance_leg_id(node, from) != Some(p.legs[0]) {
            return refuse("it names no part at rest of this custodian's own vault");
        }
        let Some(key) = node.rebalance_send_key(from) else {
            return refuse("two thirds of the receiving vault have not consented to its current key");
        };
        let (Some(sats), Some((_, nonce, _))) = (Self::rebalance_sats(node, from), Self::rebalance_target(node, from, &key)) else {
            return refuse("this custodian holds no opening of the part, or the receiving key's leaf does not rebuild");
        };
        let Some(target) = btc_tx::custody_leaf(&key.btc.members).and_then(|l| btc_tx::reserve_output(&l, &nonce)) else {
            return refuse("the part's output does not derive");
        };
        let Some((home_leaf, home_nonce, home_addr, merging)) = node.vault_coins_home(from) else {
            return refuse("this vault has no recorded key for its change");
        };
        if merging || p.change_nonce != home_nonce {
            return refuse("the change is not this vault's own current home");
        }
        let Some(home_out) = btc_tx::reserve_output(&home_leaf, &home_nonce) else {
            return refuse("the home output does not derive");
        };
        let hrp = crate::bridge::btc_net().hrp();
        let mut scripts: Vec<Vec<u8>> = Vec::with_capacity(p.inputs.len());
        let mut leaves: Vec<(CustodyLeaf, Vec<u8>)> = Vec::with_capacity(p.inputs.len());
        for (i, inp) in p.inputs.iter().enumerate() {
            if p.inputs[..i].iter().any(|x| x.txid == inp.txid && x.vout == inp.vout) {
                return refuse("an input is named twice");
            }
            if self.book.deposits.contains_key(&inp.address) {
                return refuse("a co-signed deposit coin is swept first (§BR-2)");
            }
            let Some(rec) = self.book.addresses.get(&inp.address) else {
                return refuse("an input is at an address this custodian's book does not hold");
            };
            if node.vault_of_btc_leaf(&rec.leaf_hash).is_some_and(|v| v != from) {
                return refuse("an input belongs to another vault");
            }
            let Some(leaf) = self.book.leaves.get(&rec.leaf_hash).and_then(|m| Self::leaf_of(m)).filter(|l| l.leaf_hash == rec.leaf_hash) else {
                return refuse("an input's custody leaf is not in this custodian's book");
            };
            let Some(out) = btc_tx::reserve_output(&leaf, &rec.nonce) else {
                return refuse("an input's output does not derive from its leaf and nonce");
            };
            let spk = btc_tx::p2tr_script_pubkey(&out.output_x);
            if btc_tx::reserve_address(hrp, &out.output_x) != inp.address {
                return refuse("an input's address does not derive from its leaf and nonce");
            }
            match src.tx_out(&btc_tx::txid_display_hex(&inp.txid), inp.vout) {
                Some((value, on_chain)) if value == inp.value_sats && on_chain == spk => {}
                _ => return refuse("a proposed input's value or script is not the coin's on this node's source"),
            }
            let unspent = src.utxos(&inp.address).is_some_and(|cs| cs.iter().any(|c| c.txid == inp.txid && c.vout == inp.vout && c.matured()));
            if !unspent {
                return refuse("a proposed input is not a matured unspent coin on this node's source (F2)");
            }
            scripts.push(spk);
            leaves.push((leaf, btc_tx::control_block(&out)));
        }
        let part_spk = btc_tx::p2tr_script_pubkey(&target.output_x);
        let Some(tx) = Self::rebalance_tx(p, &scripts, sats, part_spk.clone(), btc_tx::p2tr_script_pubkey(&home_out.output_x)) else {
            return refuse("the inputs do not carry the part, the fee and a change above dust");
        };
        let widest = leaves.iter().map(|(l, _)| l).max_by_key(|l| l.slot_keys.len())?;
        let vbytes = tx.estimate_vbytes(widest);
        let Some(own_rate) = src.fee_rate_sat_vb() else {
            return refuse("this node has no fee estimate of its own to judge the fee against");
        };
        if p.fee_sats < vbytes || p.fee_sats > vbytes.saturating_mul(own_rate).saturating_mul(FEE_CEIL_MULTIPLE) {
            return refuse("the fee is outside [1 sat/vB, the ceiling × this node's own estimate] (F7)");
        }
        let mut inputs: Vec<InputPlan> = Vec::with_capacity(leaves.len());
        for (i, (leaf, control)) in leaves.into_iter().enumerate() {
            let sighash = tx.sighash_script_path(i, &leaf.leaf_hash)?;
            inputs.push(InputPlan { leaf, control, sighash, depositor_sig: None });
        }
        Some(Plan { tx, inputs, legs_sats: sats, decoys: Vec::new(), decoy_fee_usdm: 0, change: Some((home_addr, home_nonce, home_leaf.leaf_hash)), rebalance_out: Some((sats, part_spk)) })
    }

    /// ⭐ spec §3g.1 — PROPOSE THIS VAULT'S REBALANCE MOVE when it is due: a part at rest with a Bitcoin leg, the receiving
    /// vault's consent to its current key, this custodian the vault's proposer this slot, and no move signed for the part
    /// yet. Inputs: this vault's own matured reserve coins, enough for the part, the fee and a change above dust.
    fn propose_rebalance_move(&mut self, node: &Node, src: &BtcSource, now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        if !Self::am_proposer(node) {
            return out;
        }
        let from = node.vault_here();
        let (Some(id), Some(sats), Some(rate), Some(me)) = (Self::rebalance_leg_id(node, from), Self::rebalance_sats(node, from), src.fee_rate_sat_vb(), self.own_point()) else { return out };
        if self.book.locks.contains_key(&id) || self.slots.values().any(|s| s.proposal.legs.first() == Some(&id)) || node.rebalance_send_key(from).is_none() {
            return out;
        }
        let Some((home_leaf, home_nonce, _, false)) = node.vault_coins_home(from) else { return out };
        let in_flight: Vec<([u8; 32], u32)> = self.slots.values().flat_map(|s| s.proposal.inputs.iter().map(|i| (i.txid, i.vout))).collect();
        let mut chosen: Vec<PayoutInput> = Vec::new();
        let mut total = 0u64;
        let probe_fee = |n: usize| {
            let probe = Payout {
                inputs: (0..n).map(|_| TxIn { txid: [0; 32], vout: 0, value_sats: 0, script_pubkey: vec![0x51, 0x20], sequence: 0 }).collect(),
                outputs: vec![TxOut { value_sats: 0, script_pubkey: vec![0u8; 34] }, TxOut { value_sats: 0, script_pubkey: vec![0u8; 34] }],
            };
            probe.estimate_vbytes(&home_leaf).saturating_mul(rate)
        };
        'scan: for (address, coin) in &self.book.addresses {
            if self.book.deposits.contains_key(address) || node.vault_of_btc_leaf(&coin.leaf_hash).is_some_and(|v| v != from) {
                continue;
            }
            let Some(utxos) = src.utxos(address) else { continue };
            for c in utxos {
                if chosen.len() >= PAYOUT_INPUTS_MAX {
                    break 'scan;
                }
                if c.matured() && !in_flight.contains(&(c.txid, c.vout)) {
                    total = total.saturating_add(c.value_sats);
                    chosen.push(PayoutInput { txid: c.txid, vout: c.vout, value_sats: c.value_sats, address: address.clone() });
                    if total >= sats.saturating_add(probe_fee(chosen.len())).saturating_add(DUST_SATS) {
                        break 'scan;
                    }
                }
            }
        }
        let fee = probe_fee(chosen.len());
        if chosen.is_empty() || total < sats.saturating_add(fee).saturating_add(DUST_SATS) {
            eprintln!("[btc-payout] not moving the rebalance's part yet: this vault's matured coins do not carry the part, the fee and a change above dust");
            return out;
        }
        chosen.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
        let epoch = node.payout_final_time_ms() / PROPOSER_SLOT_MS;
        let proposal = PayoutProposal { asset: "BTC".to_string(), epoch, proposer: me, legs: vec![id], inputs: chosen, fee_sats: fee, change_nonce: home_nonce, decoys: Vec::new(), fee_rate: rate };
        let Some(bytes) = proposal.encode() else { return out };
        // DIGITAL-CASH-PRIVACY-REVIEWED: a count of custody's own coins and a fee — custody's own move between its vaults.
        eprintln!("[btc-payout] PROPOSING the rebalance's Bitcoin move: {} coin(s), fee {fee} sats", proposal.inputs.len());
        let (fresh, mut sigs) = self.on_proposal(&bytes, node, now_ms);
        if fresh {
            out.push(WireMsg::PayoutProposal(bytes));
            out.append(&mut sigs);
        }
        out
    }

    /// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R3) — THE CONSOLIDATION: a vault's reserve coins move from under its
    /// other keys to its CURRENT key's home address, so no key the chain has replaced goes on holding coins, and the
    /// custodians it names can be released (`PegLedger::vault_key_holds`). No legs, no decoys, one output.
    /// A custodian signs it only when, on ITS OWN chain, book and source:
    ///   • the output is the home of the current key the chain records for the vault the inputs belong to
    ///     (`Node::vault_key_home_btc`) — the proposal carries only that address's public nonce, never an address;
    ///   • every input is a single-leaf reserve coin of this custodian's own book (never a co-signed deposit: that is
    ///     swept first, by exactly what its depositor signed), under a leaf that is NOT the current key's, of that
    ///     same vault, unspent and matured on its own source at the stated value and script;
    ///   • the whole value less the fee reaches the output, and the fee is inside F7 — at least 1 sat/vB, at most
    ///     `FEE_CEIL_MULTIPLE` × its own estimate;
    ///   • the move is DUE on its own reading: at once and at any fee under that ceiling when the key names a slashed
    ///     custodian or was replaced two thirds of an unbonding window ago (`Node::vault_key_move_urgent`); otherwise
    ///     only while its own fee reading is low (`fee_is_low`).
    /// §9.6 (a proposal door): (1) no PoW — a custody proposal, judged before any signature; (2) each signer's own
    /// derivation of the transaction from its own book, as every payout; (3) value — none leaves custody but the
    /// miner fee, bounded by F7 on every signer's own estimate and then booked by `Class::ReserveCost`; the output is
    /// derived from the chain's record, so no proposal can name another destination; (4) a replay spends coins that
    /// are gone — Bitcoin refuses it; (5) work — at most `PAYOUT_INPUTS_MAX` inputs, two source reads each;
    /// (6) parity with `verify`: the same input checks (book, leaf, address, value, script, unspent, matured), the
    /// same fee ceiling, and where a payout's outputs are its burns' sealed destinations, this one's is the chain's;
    /// (7) SCALE — one vault's signers (the replaced key's members), a transaction bounded by `PAYOUT_INPUTS_MAX`,
    /// nothing per bonded node; (8) AI RESISTANT — (b) code and economics bounded by (a): the only free variable is
    /// the fee, capped by every signer's own reading, and a lying proposer or a persuasive message can move coins
    /// only to the vault's own current key.
    /// cons: a vault whose coins under a replaced key are worth less than one fee plus dust cannot move them — the
    /// key stays alive (and holds its custodians) until a low enough fee; one Bitcoin fee per `PAYOUT_INPUTS_MAX` coins.
    fn verify_consolidation(&self, p: &PayoutProposal, node: &Node, src: &BtcSource) -> Option<Plan> {
        let refuse = |why: &str| {
            eprintln!("[btc-payout] ⛔ not signing the consolidation (R3): {why}");
            None::<Plan>
        };
        if !p.legs.is_empty() || !p.decoys.is_empty() || p.inputs.is_empty() {
            return refuse("a consolidation pays no legs and no decoys");
        }
        let Some(first) = self.book.addresses.get(&p.inputs[0].address) else {
            return refuse("an input is at an address this custodian's book does not hold");
        };
        // the vault the coins belong to: the one whose key record names their leaf; a coin from before the record is
        // this custodian's own vault's
        let Some(vault) = node.vault_of_btc_leaf(&first.leaf_hash).or_else(|| node.custodian_id().map(|_| node.vault_here())) else {
            return refuse("the inputs' key belongs to no vault this node's chain records");
        };
        // the vault's own current key — or the RECEIVING vault's while this vault's merge is due (R7: coins first)
        let Some((home_leaf, home_nonce, home_addr, merging)) = node.vault_coins_home(vault) else {
            return refuse("the vault has no recorded key to move its coins under");
        };
        if p.change_nonce != home_nonce {
            return refuse("the output is not the vault's current key's home address");
        }
        let Some(home_out) = btc_tx::reserve_output(&home_leaf, &home_nonce) else {
            return refuse("the home output does not derive");
        };
        let hrp = crate::bridge::btc_net().hrp();
        let mut scripts: Vec<Vec<u8>> = Vec::with_capacity(p.inputs.len());
        let mut leaves: Vec<(CustodyLeaf, Vec<u8>)> = Vec::with_capacity(p.inputs.len());
        let mut urgent = merging; // R8: a due merge is done at once, at any fee under the ceiling
        for (i, inp) in p.inputs.iter().enumerate() {
            if p.inputs[..i].iter().any(|x| x.txid == inp.txid && x.vout == inp.vout) {
                return refuse("an input is named twice");
            }
            if self.book.deposits.contains_key(&inp.address) {
                return refuse("a co-signed deposit coin is swept first, never consolidated (§BR-2)");
            }
            let Some(rec) = self.book.addresses.get(&inp.address) else {
                return refuse("an input is at an address this custodian's book does not hold");
            };
            if rec.leaf_hash == home_leaf.leaf_hash {
                return refuse("an input is already under the vault's current key");
            }
            if node.vault_of_btc_leaf(&rec.leaf_hash).is_some_and(|v| v != vault) {
                return refuse("the inputs belong to two vaults");
            }
            let Some(leaf) = self.book.leaves.get(&rec.leaf_hash).and_then(|m| Self::leaf_of(m)).filter(|l| l.leaf_hash == rec.leaf_hash) else {
                return refuse("an input's custody leaf is not in this custodian's book");
            };
            let Some(out) = btc_tx::reserve_output(&leaf, &rec.nonce) else {
                return refuse("an input's output does not derive from its leaf and nonce");
            };
            let spk = btc_tx::p2tr_script_pubkey(&out.output_x);
            if btc_tx::reserve_address(hrp, &out.output_x) != inp.address {
                return refuse("an input's address does not derive from its leaf and nonce");
            }
            let Some((value, on_chain_spk)) = src.tx_out(&btc_tx::txid_display_hex(&inp.txid), inp.vout) else {
                return refuse("this node's source does not show a proposed input coin");
            };
            if value != inp.value_sats || on_chain_spk != spk {
                return refuse("a proposed input's value or script is not the coin's");
            }
            let Some(coins) = src.utxos(&inp.address) else {
                return refuse("this node's source does not list an input address's coins");
            };
            let Some(coin) = coins.iter().find(|c| c.txid == inp.txid && c.vout == inp.vout) else {
                return refuse("a proposed input is not an unspent coin on this node's source");
            };
            if !coin.matured() {
                return refuse("a proposed input has not matured (F2)");
            }
            urgent |= node.vault_key_move_urgent(vault, &rec.leaf_hash);
            scripts.push(spk);
            leaves.push((leaf, btc_tx::control_block(&out)));
        }
        let Some(tx) = Self::consolidation_tx(p, &scripts, btc_tx::p2tr_script_pubkey(&home_out.output_x)) else {
            return refuse("the inputs do not carry the fee and an output above dust");
        };
        let mut widest = &leaves[0].0;
        for (l, _) in &leaves {
            if l.slot_keys.len() > widest.slot_keys.len() {
                widest = l;
            }
        }
        let vbytes = tx.estimate_vbytes(widest);
        let Some(own_rate) = src.fee_rate_sat_vb() else {
            return refuse("this node has no fee estimate of its own to judge the fee against");
        };
        if p.fee_sats < vbytes || p.fee_sats > vbytes.saturating_mul(own_rate).saturating_mul(FEE_CEIL_MULTIPLE) {
            return refuse("the fee is outside [1 sat/vB, the ceiling × this node's own estimate] (F7)");
        }
        if !urgent && !self.fee_is_low(own_rate, false) {
            return refuse("not due yet — the fee is not low on this node's own reading and no key in it is past its deadline");
        }
        let mut inputs: Vec<InputPlan> = Vec::with_capacity(leaves.len());
        for (i, (leaf, control)) in leaves.into_iter().enumerate() {
            let sighash = tx.sighash_script_path(i, &leaf.leaf_hash)?;
            inputs.push(InputPlan { leaf, control, sighash, depositor_sig: None });
        }
        Some(Plan { tx, inputs, legs_sats: 0, decoys: Vec::new(), decoy_fee_usdm: 0, change: Some((home_addr, home_nonce, home_leaf.leaf_hash)), rebalance_out: None })
    }

    /// Is `slot`'s proposal a consolidation (no legs, and not a co-signed deposit's sweep)?
    fn is_consolidation(&self, p: &PayoutProposal) -> bool {
        p.legs.is_empty() && !(p.inputs.len() == 1 && self.book.deposits.contains_key(&p.inputs[0].address))
    }

    /// ⭐⭐ SAFE AT SCALE, stage three (finding A-F21: the ledger follows every coin) — JUDGE A CONSOLIDATION'S FEE FROM
    /// THIS NODE'S OWN CHAIN AND ITS OWN BITCOIN SOURCE, given only the evidence a cost signature carries
    /// (`CostEvidence`): `(ledger asset, fee in sats, Bitcoin txid)` when, here and now,
    ///   • the output is the home of a key THIS chain records alive for this custodian's own vault;
    ///   • every input's address derives from the nonce the evidence states under the leaf of an alive key of that
    ///     vault (rebuilt from the record's own inputs) — or, for a coin from before the record, under a leaf this
    ///     custodian's own book holds — and that leaf is not the output's;
    ///   • its own source shows each input's funding output at the stated value and script — so the fee is the
    ///     inputs' true total less the one output, not a number anyone stated;
    ///   • the transaction those inputs and that output spell is on its own source at the depth a payout of that
    ///     value settles at.
    /// A custodian that never saw the proposal (it joined after, or was down) judges exactly what one that signed
    /// it judges. A deposit's sweep (its fee is the depositor's) and a cash-out (its fee is its pieces' allowances)
    /// derive no home nonce and are judged `None`.
    /// AI RESISTANT: (b) code over this node's own sources — nothing in the evidence is believed: an overstated
    /// input value fails the source read, another destination is not a home of this vault, an unconfirmed or
    /// invented transaction has no depth. What it cannot tell is a quorum of the old key overpaying its own fee,
    /// which F7 bounds at signing and that key's bonds answer for.
    pub fn judge_cost(&self, evidence: &[u8], node: &Node, src: &BtcSource) -> Option<(u32, u64, [u8; 32])> {
        let (p, coins, rebalance_out) = CostEvidence::decode_full(evidence)?;
        if p.asset != "BTC" || !p.decoys.is_empty() {
            return None;
        }
        node.custodian_id()?;
        let vault = node.vault_here();
        let rows = node.peg().vault_keys(vault);
        // …or, while this vault's merge is due, the home of the receiving vault's current key (R7: coins first)
        let merging = node.vault_coins_home(vault).filter(|h| h.3).map(|(leaf, nonce, address, _)| (leaf, nonce, address));
        let (home_leaf, home_nonce, _) = rows.iter().filter_map(Node::vault_key_home_btc).chain(merging).find(|(_, n, _)| *n == p.change_nonce)?;
        let hrp = crate::bridge::btc_net().hrp();
        let mut scripts: Vec<Vec<u8>> = Vec::with_capacity(p.inputs.len());
        let mut in_total = 0u64;
        for (i, (inp, coin)) in p.inputs.iter().zip(&coins).enumerate() {
            // a consolidation moves coins OFF a key onto its vault's home; a rebalance move may spend coins under the current key
            if p.inputs[..i].iter().any(|x| x.txid == inp.txid && x.vout == inp.vout) || (rebalance_out.is_none() && coin.leaf_hash == home_leaf.leaf_hash) {
                return None;
            }
            let members = rows.iter().find(|k| k.btc.leaf == coin.leaf_hash).map(|k| &k.btc.members).or_else(|| self.book.leaves.get(&coin.leaf_hash))?;
            let leaf = Self::leaf_of(members).filter(|l| l.leaf_hash == coin.leaf_hash)?;
            let out = btc_tx::reserve_output(&leaf, &coin.nonce)?;
            if btc_tx::reserve_address(hrp, &out.output_x) != inp.address {
                return None;
            }
            let spk = btc_tx::p2tr_script_pubkey(&out.output_x);
            let (value, on_chain_spk) = src.tx_out(&btc_tx::txid_display_hex(&inp.txid), inp.vout)?;
            if value != inp.value_sats || on_chain_spk != spk {
                return None;
            }
            in_total = in_total.checked_add(value)?;
            scripts.push(spk);
        }
        let home_out = btc_tx::reserve_output(&home_leaf, &home_nonce)?;
        let home_spk = btc_tx::p2tr_script_pubkey(&home_out.output_x);
        // spec §3g.1: a rebalance move is its part's output then the change home — the fee is the inputs' true total less
        // both, so the part (which the carve took out of the ledger) is never booked as a fee
        let tx = match &rebalance_out {
            None => Self::consolidation_tx(&p, &scripts, home_spk)?,
            Some((sats, spk)) => Self::rebalance_tx(&p, &scripts, *sats, spk.clone(), home_spk)?,
        };
        let txid = tx.txid();
        let confs = src.tx_confirmations(&btc_tx::txid_display_hex(&txid))?;
        (confs >= required_confirmations(in_total)).then_some((crate::peg::NATIVE_PEG_ASSET_ID, p.fee_sats, txid))
    }

    /// The consolidations this custodian saw confirmed whose fee the chain has not booked: the evidence the cost lane
    /// signs from (`Node::own_reserve_cost_sig`), by Bitcoin txid.
    #[must_use]
    pub fn cost_evidence(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.book.costs.iter().map(|(t, e)| (*t, e.clone())).collect()
    }

    /// Keep the evidence of a consolidation ANOTHER custodian of this vault signed for, once this node's own source
    /// judged it true (`judge_cost`): from here it counts toward this custodian's solvency reading exactly as its
    /// own does, so the fee on its way to the ledger does not hold the vault's deposits on the custodians that did
    /// not sign the move. Bounded like the book's own (`COSTS_PENDING_MAX`); it leaves when the chain books it.
    /// CACHE-ONLY: this custodian's own record of a Bitcoin fact it judged; the ledger moves only by `Class::ReserveCost`.
    pub fn hold_cost_evidence(&mut self, txid: [u8; 32], evidence: &[u8]) {
        if self.book.costs.contains_key(&txid) {
            return;
        }
        while self.book.costs.len() >= COSTS_PENDING_MAX {
            self.book.costs.pop_first();
        }
        self.book.costs.insert(txid, evidence.to_vec());
        self.save();
    }

    /// The chain booked the cost of `txid` (or this node judged it is not a cost of its vault): its evidence leaves.
    pub fn cost_done(&mut self, txid: &[u8; 32]) {
        if self.book.costs.remove(txid).is_some() {
            self.save();
        }
    }

    /// The total this custodian's last complete scan of its own Bitcoin source showed at its book's addresses, in
    /// sats — `None` until every address answered once. What the merge lane reads for "coins first".
    #[must_use]
    pub fn coins_seen(&self) -> Option<u128> {
        self.coin_scan.as_ref().map(|(_, seen)| *seen)
    }

    /// What this custodian's last complete scan of its own source showed: the custody leaves (by hash) with a coin
    /// under them — `None` until every address answered, or while the coins it sees do not account for the whole
    /// reserve its opening counts (it then cannot say a key is empty: a coin it does not know may sit under it).
    #[must_use]
    pub fn coin_view(&self, node: &Node) -> Option<std::collections::BTreeSet<[u8; 32]>> {
        let (holding, seen) = self.coin_scan.as_ref()?;
        (*seen >= node.custodian_reserve_value()?).then(|| holding.clone())
    }

    /// ⭐ R3 — PROPOSE THE CONSOLIDATION THIS NODE'S BOOK AND CHAIN SAY IS DUE: for one replaced (or pre-record) leaf
    /// whose key this node holds, the matured coins under it, to the home of the vault's current key. Whose turn: the
    /// leaf's own members in key order, one per proposer slot — every holder of the old key takes a turn, seated or
    /// not, because after a large change of members the old key's holders may be the only ones who know its coins.
    /// Proposed only when due at the proposer's stricter reading (`fee_is_low(…, true)`) or past the key's deadline.
    fn propose_consolidation(&mut self, node: &Node, src: &BtcSource, now_ms: u64, epoch: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        let Some(me) = self.own_point() else { return out };
        let Some(rate) = src.fee_rate_sat_vb() else { return out };
        let in_flight: Vec<([u8; 32], u32)> = self.slots.values().flat_map(|s| s.proposal.inputs.iter().map(|i| (i.txid, i.vout))).collect();
        // the leaves this node's book holds coins addresses under, each with the vault it belongs to
        let mut by_leaf: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
        for (address, coin) in &self.book.addresses {
            if !self.book.deposits.contains_key(address) {
                by_leaf.entry(coin.leaf_hash).or_default().push(address.clone());
            }
        }
        for (leaf_hash, addresses) in by_leaf {
            let Some(members) = self.book.leaves.get(&leaf_hash) else { continue };
            let Some(vault) = node.vault_of_btc_leaf(&leaf_hash).or_else(|| node.custodian_id().map(|_| node.vault_here())) else { continue };
            let Some((home_leaf, home_nonce, _, merging)) = node.vault_coins_home(vault) else { continue };
            if home_leaf.leaf_hash == leaf_hash {
                continue; // already under the key the vault's coins belong under
            }
            let mut holders: Vec<[u8; 32]> = members.iter().map(|(x, _)| *x).collect();
            holders.sort_unstable();
            if holders.is_empty() || holders[epoch as usize % holders.len()] != me {
                continue;
            }
            if !(merging || node.vault_key_move_urgent(vault, &leaf_hash) || self.fee_is_low(rate, true)) {
                continue;
            }
            let Some(leaf) = Self::leaf_of(members).filter(|l| l.leaf_hash == leaf_hash) else { continue };
            let mut chosen: Vec<PayoutInput> = Vec::new();
            for address in &addresses {
                let Some(utxos) = src.utxos(address) else { continue };
                for c in utxos {
                    if chosen.len() < PAYOUT_INPUTS_MAX && c.matured() && !in_flight.contains(&(c.txid, c.vout)) {
                        chosen.push(PayoutInput { txid: c.txid, vout: c.vout, value_sats: c.value_sats, address: address.clone() });
                    }
                }
            }
            if chosen.is_empty() {
                continue;
            }
            chosen.sort_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
            let probe = Payout {
                inputs: chosen.iter().map(|i| TxIn { txid: i.txid, vout: i.vout, value_sats: i.value_sats, script_pubkey: vec![0x51, 0x20], sequence: 0 }).collect(),
                outputs: vec![TxOut { value_sats: 0, script_pubkey: vec![0u8; 34] }],
            };
            let fee = probe.estimate_vbytes(&leaf).saturating_mul(rate);
            let total: u64 = chosen.iter().map(|c| c.value_sats).sum();
            if total < fee.saturating_add(DUST_SATS) {
                // DIGITAL-CASH-PRIVACY-REVIEWED: custody's own coin total under one of its own keys and a fee — no user's value.
                eprintln!("[btc-payout] not consolidating yet: the {total} sats under a replaced key do not carry the fee ({fee} sats) and an output above dust");
                continue;
            }
            let proposal = PayoutProposal { asset: "BTC".to_string(), epoch, proposer: me, legs: Vec::new(), inputs: chosen, fee_sats: fee, change_nonce: home_nonce, decoys: Vec::new(), fee_rate: rate };
            let Some(bytes) = proposal.encode() else { continue };
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count of custody's own coins and a fee — no address, no user's value.
            eprintln!("[btc-payout] PROPOSING a consolidation: {} coin(s) from under a replaced key to the vault's current key, fee {fee} sats", proposal.inputs.len());
            let (fresh, mut sigs) = self.on_proposal(&bytes, node, now_ms);
            if fresh {
                out.push(WireMsg::PayoutProposal(bytes));
                out.append(&mut sigs);
            }
            break; // one consolidation per poll
        }
        out
    }

    /// ⭐ THE POLL'S SCAN OF THIS BOOK'S ADDRESSES ON THIS NODE'S OWN SOURCE — one read per address, shared by the
    /// solvency reading (DB-122 F6), the key lane's coin view and the book's own upkeep:
    ///   • the total seen, with the fees of consolidations this custodian has itself judged confirmed and that the
    ///     chain has not booked yet counted back in, is compared with its opening's reserve — a fee in flight to
    ///     the ledger never holds the vault's deposits;
    ///   • the leaves with a coin under them are kept for the key lane (`coin_view`);
    ///   • a HOME address of a key the chain no longer records, with no coin left, leaves the book.
    /// An unanswered address is not evidence: nothing is concluded from a partial scan.
    fn scan_coins(&mut self, node: &mut Node, src: &BtcSource) {
        let mut seen: u128 = 0;
        let mut holding: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        let mut empty: Vec<String> = Vec::new();
        let mut answered_all = true;
        for (address, coin) in &self.book.addresses {
            match src.utxos(address) {
                Some(coins) if coins.is_empty() => empty.push(address.clone()),
                Some(coins) => {
                    holding.insert(coin.leaf_hash);
                    for c in coins {
                        seen = seen.saturating_add(u128::from(c.value_sats));
                    }
                }
                None => answered_all = false,
            }
        }
        if !answered_all {
            return; // an unanswered address is not evidence of missing coins
        }
        // a retired key's empty home leaves the book (a home is re-booked from the record while its key is alive)
        let mut dropped = false;
        for address in empty {
            let Some(coin) = self.book.addresses.get(&address) else { continue };
            let is_home = coin.nonce[..] == btc_tx::home_nonce(&coin.leaf_hash)[..];
            if is_home && node.vault_of_btc_leaf(&coin.leaf_hash).is_none() {
                self.book.addresses.remove(&address);
                dropped = true;
            }
        }
        if dropped {
            let used: std::collections::BTreeSet<[u8; 32]> = self.book.addresses.values().map(|c| c.leaf_hash).collect();
            let live = node.custody_leaf_current().map(|l| l.leaf_hash);
            self.book.leaves.retain(|h, _| used.contains(h) || Some(*h) == live || node.vault_of_btc_leaf(h).is_some());
            self.save();
        }
        self.coin_scan = Some((holding, seen));
        if let Some(r_val) = node.custodian_reserve_value() {
            let in_flight: u128 = self.book.costs.values().filter_map(|e| self.judge_cost(e, node, src)).map(|(_, fee, _)| u128::from(fee)).sum();
            node.set_reserve_solvency_hold(r_val > 0 && seen.saturating_add(in_flight) < r_val);
        }
    }

    /// ⭐ THE COIN-LIST LANE, this custodian's own turn (`CoinShare`): while its source shows fewer coins than its
    /// opening counts, it asks its vault — at most once per `COIN_SHARE_EVERY_MS`, each ask a new round.
    fn coin_share_ask(&mut self, node: &Node, now_ms: u64) -> Option<WireMsg> {
        let me = node.custodian_id()?;
        let (_, seen) = self.coin_scan.as_ref()?;
        if *seen >= node.custodian_reserve_value()? || now_ms.saturating_sub(self.coin_ask.1) < COIN_SHARE_EVERY_MS {
            return None;
        }
        if node.custody_set_here().len() < 2 {
            return None; // nobody to ask
        }
        self.coin_ask = (self.coin_ask.0.wrapping_add(1), now_ms);
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence — no address, amount or owner.
        eprintln!("[btc-payout] this custodian's source shows fewer coins than its opening counts — asking its vault for the coin list");
        Some(WireMsg::CoinShare(CoinShare::Ask { vault: node.vault_here(), from: me, round: self.coin_ask.0 }.encode()))
    }

    /// ⭐ THE COIN-LIST LANE, a message arrived. An ASK from a custodian of this node's own vault is answered when it is
    /// this custodian's round (the asker's seat plus one plus `round`, among the vault's other seats), at most once
    /// per asker per `COIN_SHARE_EVERY_MS`, with the nonce and leaf of every single-leaf coin address of its book —
    /// sealed to the asker's registered key, `COIN_SHARE_CHUNK` entries a message. A GIVE addressed here is opened and
    /// each entry is booked ONLY IF its address derives under a key this node's own chain records for its vault and
    /// its own source shows a coin there. `bytes` is the lane's message, already opened from its signed envelope by
    /// the runtime, and `sender` the bonded custodian that signed it (A-F30, `node::opening_share::SignedShare`).
    /// `(relay, messages to send)`: a message that does not decode, or an ask naming another custodian than its
    /// signer, is not relayed; the messages returned are the lane's own, signed by the runtime before they leave.
    pub fn on_coin_share(&mut self, bytes: &[u8], sender: [u8; 32], node: &Node, now_ms: u64) -> (bool, Vec<WireMsg>) {
        let Some(msg) = CoinShare::decode(bytes) else { return (false, Vec::new()) };
        if matches!(&msg, CoinShare::Ask { from, .. } if *from != sender) {
            return (false, Vec::new()); // nobody asks in another custodian's name
        }
        let Some(me) = node.custodian_id() else { return (true, Vec::new()) };
        match msg {
            CoinShare::Ask { vault, from, round } => {
                let seats = node.custody_set_here();
                if vault != node.vault_here() || from == me || !seats.contains(&from) {
                    return (true, Vec::new());
                }
                // one giver per round: the other seats in order, starting after the asker
                let others: Vec<[u8; 32]> = {
                    let at = seats.iter().position(|s| *s == from).unwrap_or(0);
                    seats.iter().cycle().skip(at + 1).take(seats.len() - 1).copied().collect()
                };
                if others.is_empty() || others[round as usize % others.len()] != me {
                    return (true, Vec::new());
                }
                self.coin_gave.retain(|_, t| now_ms < t.saturating_add(COIN_SHARE_EVERY_MS));
                if self.coin_gave.contains_key(&from) {
                    return (true, Vec::new());
                }
                self.coin_gave.insert(from, now_ms);
                let entries: Vec<CoinAddress> =
                    self.book.addresses.iter().filter(|(a, _)| !self.book.deposits.contains_key(*a)).map(|(_, c)| c.clone()).filter(|c| c.nonce.len() <= 64).collect();
                let mut out = Vec::new();
                for chunk in entries.chunks(COIN_SHARE_CHUNK) {
                    let Ok(body) = postcard::to_allocvec(&chunk.to_vec()) else { continue };
                    if let Some(sealed) = node.seal_to_vault_custodian(&from, &body, COIN_SHARE_BODY_MAX) {
                        out.push(WireMsg::CoinShare(CoinShare::Give { to: from, sealed }.encode()));
                    }
                }
                (true, out)
            }
            CoinShare::Give { to, sealed } => {
                if to != me {
                    return (true, Vec::new());
                }
                let Some(entries) = node.open_as_vault_custodian(&sealed, COIN_SHARE_BODY_MAX).and_then(|b| crate::chain_object::decode_exact::<Vec<CoinAddress>>(&b)) else {
                    return (true, Vec::new());
                };
                let Some(src) = btc_source(crate::bridge::btc_net()) else { return (true, Vec::new()) };
                let hrp = crate::bridge::btc_net().hrp();
                let vault = node.vault_here();
                let mut booked = 0usize;
                for c in entries.into_iter().take(COIN_SHARE_CHUNK) {
                    // only under a key THIS chain records for this custodian's vault
                    let Some(k) = node.peg().vault_keys(vault).iter().find(|k| k.btc.leaf == c.leaf_hash) else { continue };
                    let Some(leaf) = Self::leaf_of(&k.btc.members).filter(|l| l.leaf_hash == c.leaf_hash) else { continue };
                    let Some(out) = btc_tx::reserve_output(&leaf, &c.nonce) else { continue };
                    let address = btc_tx::reserve_address(hrp, &out.output_x);
                    if self.book.addresses.contains_key(&address) {
                        continue;
                    }
                    // and only where this node's own source shows a coin: a made-up entry books nothing
                    if !src.utxos(&address).is_some_and(|coins| !coins.is_empty()) {
                        continue;
                    }
                    self.book.leaves.entry(leaf.leaf_hash).or_insert_with(|| k.btc.members.clone());
                    self.book.addresses.insert(address, c);
                    booked += 1;
                }
                if booked > 0 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a count of custody's own coin addresses — no address, amount or owner.
                    eprintln!("[btc-payout] booked {booked} coin address(es) of this vault from a custodian's sealed list — each derives under a key this chain records and holds a coin on this node's own source");
                    self.save();
                }
                (true, Vec::new())
            }
        }
    }

    /// OWED, the hand-over — does this custodian hold the leg of the cash-out that burned `nf` (a ticket not yet opened,
    /// an obligation, or the object's kept parts)?
    #[must_use]
    pub fn holds_leg(&self, nf: &[u8; 32]) -> bool {
        self.book.obligations.contains_key(nf) || self.book.tickets.contains_key(nf) || self.book.leg_proofs.contains_key(nf)
    }

    /// OWED, the hand-over — a payout of this custodian's vault named the burn `nf`. When this node's own chain shows
    /// that release owed and neither payout lane holds a leg for it (`held_elsewhere`: the Monero lane's book), the
    /// burn joins the legs this custodian asks its vault for. At most `LEG_WANT_MAX` at once: a further one is noted
    /// when a payout names it again after one of these left.
    /// CACHE-ONLY: a list of what THIS custodian is missing; it decides nothing for the chain.
    pub fn note_leg_wanted(&mut self, node: &Node, nf: &[u8; 32], held_elsewhere: bool) {
        if held_elsewhere || self.holds_leg(nf) || self.leg_want.contains_key(nf) || self.leg_want.len() >= LEG_WANT_MAX {
            return;
        }
        if node.custodian_id().is_none() || !node.peg().release_pending(nf) {
            return;
        }
        self.leg_want.insert(*nf, (0, 0));
        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence and a count — no nullifier, amount or destination.
        eprintln!(
            "[btc-payout] a payout names an owed cash-out this custodian holds no leg for (it joined after that block left its window) — asking its vault for the leg ({} asked for)",
            self.leg_want.len()
        );
    }

    /// OWED, the hand-over — this custodian's own turn: forget every wanted burn it now holds or the chain shows paid,
    /// drop the kept parts of every cash-out the chain shows paid, and ask its vault for each burn still wanted, at
    /// most once per `LEG_SHARE_EVERY_MS`, each ask a new round (so the next seat answers). The messages are the
    /// lane's own; the runtime signs each into the hand-over envelope before it leaves.
    pub fn leg_share_tick(&mut self, node: &Node, now_ms: u64) -> Vec<WireMsg> {
        let before = self.book.leg_proofs.len();
        self.book.leg_proofs.retain(|nf, _| node.peg().release_pending(nf));
        if self.book.leg_proofs.len() != before {
            self.save();
        }
        let held: Vec<[u8; 32]> = self.leg_want.keys().filter(|nf| self.holds_leg(nf) || !node.peg().release_pending(nf)).copied().collect();
        for nf in held {
            self.leg_want.remove(&nf);
        }
        self.leg_gave.retain(|_, t| now_ms < t.saturating_add(LEG_SHARE_EVERY_MS));
        let Some(me) = node.custodian_id() else { return Vec::new() };
        if self.leg_want.is_empty() || node.custody_set_here().len() < 2 {
            return Vec::new(); // nothing wanted, or nobody to ask
        }
        let vault = node.vault_here();
        let mut out = Vec::new();
        for (nf, (round, asked_ms)) in self.leg_want.iter_mut() {
            if *asked_ms != 0 && now_ms.saturating_sub(*asked_ms) < LEG_SHARE_EVERY_MS {
                continue;
            }
            *round = round.wrapping_add(1);
            *asked_ms = now_ms.max(1);
            out.push(WireMsg::LegShare(LegShare::Ask { vault, from: me, nullifier: *nf, round: *round }.encode()));
        }
        out
    }

    /// OWED, the hand-over — a message of the lane arrived, already opened from its envelope by the runtime: `body`
    /// is the lane's message and `sender` the bonded custodian that signed it (`Node::share_signer`; the runtime's
    /// bound on each signer's messages ran before this). `(relay, messages to send)`: an ask that names another
    /// custodian than its signer is not relayed; the messages returned are the lane's own, signed by the runtime.
    /// An ASK from a custodian of this node's own vault is answered when it is this custodian's round (the asker's
    /// seat plus `round`, among the vault's other seats), it holds the kept parts of that cash-out, and it has not
    /// answered this asker for this burn within `LEG_SHARE_EVERY_MS`. A GIVE addressed here for a burn this custodian
    /// asked for is handed to `Node::recover_peg_out_leg_signed`, which books the leg only if the custody quorum signed
    /// exactly these parts for a release this node's own ledger shows owed; the next `absorb` books the ticket.
    pub fn on_leg_share(&mut self, body: &[u8], sender: [u8; 32], node: &mut Node, now_ms: u64) -> (bool, Vec<WireMsg>) {
        let Some(msg) = LegShare::decode(body) else { return (false, Vec::new()) };
        if matches!(&msg, LegShare::Ask { from, .. } if *from != sender) {
            return (false, Vec::new()); // nobody asks in another custodian's name
        }
        let verifier = crate::pqauth::MlDsaVerifier;
        let Some(me) = node.custodian_id() else { return (true, Vec::new()) };
        match msg {
            LegShare::Ask { vault, from, nullifier, round } => {
                let seats = node.custody_set_here();
                if vault != node.vault_here() || from == me || !seats.contains(&from) {
                    return (true, Vec::new());
                }
                // one giver per round: the other seats in order, starting after the asker
                let others: Vec<[u8; 32]> = {
                    let at = seats.iter().position(|s| *s == from).unwrap_or(0);
                    seats.iter().cycle().skip(at + 1).take(seats.len() - 1).copied().collect()
                };
                if others.is_empty() || others[round as usize % others.len()] != me {
                    return (true, Vec::new());
                }
                if !node.peg().release_pending(&nullifier) || self.leg_gave.contains_key(&(from, nullifier)) {
                    return (true, Vec::new());
                }
                // this custodian holds no kept parts for it (or an empty entry, which is none): the next round asks the next seat
                let kept: Vec<u8> = match self.book.leg_proofs.get(&nullifier) {
                    Some(parts) if !parts.is_empty() => parts.clone(),
                    _ => return (true, Vec::new()),
                };
                let give = LegShare::Give { to: from, nullifier, proof: kept }.encode();
                self.leg_gave.insert((from, nullifier), now_ms);
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence — no nullifier, amount or destination.
                eprintln!("[btc-payout] handed a vault mate the signed parts of an owed cash-out it holds no leg for");
                (true, vec![WireMsg::LegShare(give)])
            }
            LegShare::Give { to, nullifier, proof } => {
                if to != me || !self.leg_want.contains_key(&nullifier) || self.holds_leg(&nullifier) {
                    return (true, Vec::new());
                }
                let Some(proof) = crate::peg_out_tx::LegProof::decode(&proof) else { return (true, Vec::new()) };
                // dated at this node's tip: every burn in its certified ledger had applied by then (the window recovery's rule)
                let at = node.tip_height();
                if node.recover_peg_out_leg_signed(nullifier, &proof, &verifier, at) {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence — no nullifier, amount or destination.
                    eprintln!("[btc-payout] a vault mate's hand-over opened this custodian's leg of an owed cash-out — the custody quorum signed exactly these parts");
                } else {
                    eprintln!("[btc-payout] ⛔ a hand-over for an owed cash-out was NOT used: the custody quorum did not sign these parts, or no envelope in them opens here");
                }
                (true, Vec::new())
            }
        }
    }

    /// ⭐ §BR-8 B8-a — the decoy legs the decoy rule gives a batch of `leg_units` at `fee_rate` under `seed`, from THIS node's
    /// chain state (the epoch's budget in sats at the BTC TWAP, the open obligations, the bonded custodians). One function for
    /// the proposer and every signer.
    fn decoy_plan(node: &Node, leg_units: &[u64], fee_rate: u64, seed: &[u8; 32]) -> Vec<([u8; 32], u64)> {
        let budget_sats = node
            .peg()
            .twap7(crate::peg::NATIVE_PEG_ASSET_ID)
            .filter(|p| *p > 0)
            .map_or(0, |p| u64::try_from(u128::from(node.peg().decoy_budget_left()) * crate::liquidation::PRICE_SCALE / p).unwrap_or(u64::MAX));
        let cands: Vec<([u8; 32], u128)> = node.validators().decoy_candidates().into_iter().map(|(id, w, _)| (id, w)).collect();
        crate::decoy_tx::decoy_legs(leg_units, budget_sats, fee_rate, &cands, seed, node.peg().open_decoys().len())
    }

    /// The decoy legs' fee in USDm atomic at the BTC TWAP (what the budget and the surplus buffer pay).
    fn decoy_fee_usdm(node: &Node, n: usize, fee_rate: u64) -> u64 {
        let sats = (n as u64).saturating_mul(crate::decoy_tx::DECOY_VBYTES).saturating_mul(fee_rate);
        node.peg().twap7(crate::peg::NATIVE_PEG_ASSET_ID).map_or(0, |p| u64::try_from(u128::from(sats) * p / crate::liquidation::PRICE_SCALE).unwrap_or(u64::MAX))
    }

    /// The decoy output script of validator `vid`: the BIP-86 key-path output of its registered custody point.
    fn decoy_spk(node: &Node, vid: &[u8; 32]) -> Option<Vec<u8>> {
        let (_, _, x) = node.validators().decoy_candidates().into_iter().find(|(id, _, _)| id == vid)?;
        Some(btc_tx::p2tr_script_pubkey(&btc_tx::bip86_output_from_xonly(&x)?))
    }

    /// §BR-8 — a returned decoy's reserve address joins this custodian's book (the return is a reserve coin the next payout
    /// may spend, like a payout's change).
    pub fn book_reserve_address(&mut self, address: String, nonce: [u8; 32], leaf_hash: [u8; 32]) {
        if !self.book.addresses.contains_key(&address) {
            self.book.addresses.insert(address, CoinAddress { nonce: nonce.to_vec(), leaf_hash });
            self.save();
        }
    }

    /// §BR-8 — the signed batches with decoys this lane holds, for custody to attest (`(payout txid, decoys, fee USDm)`).
    pub fn decoy_batches(&self) -> Vec<([u8; 32], Vec<crate::decoy_tx::DecoyEntry>, u64)> {
        self.slots.values().filter(|s| !s.plan.decoys.is_empty()).map(|s| (s.plan.tx.txid(), s.plan.decoys.clone(), s.plan.decoy_fee_usdm)).collect()
    }

    fn verify(&self, p: &PayoutProposal, id: &[u8; 32], node: &Node, src: &BtcSource) -> Option<Plan> {
        if p.asset != "BTC" {
            return None;
        }
        // §BR-2: a proposal spending a co-signed deposit is a SWEEP, judged by its own rule (exactly what the depositor
        // signed); a deposit coin inside any other payout is refused below.
        if p.inputs.len() == 1 && self.book.deposits.contains_key(&p.inputs[0].address) {
            return self.verify_sweep(p, node, src);
        }
        // SAFE AT SCALE, stage three: any other proposal with no legs is a CONSOLIDATION, judged by its own rule — reserve
        // coins from under this vault's other keys to its current key's home, for nobody but the vault itself.
        if p.legs.is_empty() {
            return self.verify_consolidation(p, node, src);
        }
        // spec §3g.1: a proposal whose one leg is this vault's part at rest is the REBALANCE MOVE, judged by its own rule —
        // the part to the key the receiving vault consented to, the rest home (it names no burn)
        if p.legs.len() == 1 && node.custodian_id().is_some() && Self::rebalance_leg_id(node, node.vault_here()) == Some(p.legs[0]) {
            return self.verify_rebalance_move(p, node, src);
        }
        if node.custodian_id().is_none() {
            // a key holder the chain no longer seats signs the move of its old key's coins and nothing else
            return None;
        }
        let net = crate::bridge::btc_net();
        let hrp = net.hrp();
        let finalized = node.payout_final_height(); // SPEED L7 + FINALITY OVERLAY (2026-11-17): vote-final OR 64 levels deep (Node::payout_final_height)
        let seed = epoch_seed("BTC", p.epoch);
        let mut outputs: Vec<TxOut> = Vec::with_capacity(p.legs.len() + 1);
        let mut legs_sats = 0u64;
        let mut paid_sats = 0u64;
        // A-F21 / A-F35: every leg carries the same share of THIS proposal's fee — recomputed here, never read from the proposer
        let share = leg_fee_share(p.fee_sats, p.legs.len())?;
        let mut last_key: Option<u64> = None;
        for (i, nf) in p.legs.iter().enumerate() {
            if p.legs[..i].contains(nf) {
                return None;
            }
            if !node.peg().release_pending(nf) {
                eprintln!("[btc-payout] not signing: a leg is not an owed burn on this node's chain");
                return None;
            }
            let Some(ob) = self.book.obligations.get(nf) else {
                eprintln!("[btc-payout] not signing: this custodian holds no sealed leg for a proposed burn");
                return None;
            };
            if !leg_is_payable(ob, finalized, node.payout_final_time_ms()) {
                eprintln!("[btc-payout] not signing yet: the burn's block or the piece's sealed pay-after is not finalized here (F1 / §BR-1)");
                return None;
            }
            let (dest_net, spk) = btc_tx::script_pubkey_for_address(&ob.redeem_to)?;
            if dest_net != net || ob.release_sats == 0 {
                eprintln!("[btc-payout] ⛔ not signing: a destination is not on this reserve's network");
                return None;
            }
            let key = payout_order_key(nf, &seed);
            if let Some(prev) = last_key {
                if prev > key {
                    eprintln!("[btc-payout] not signing: the legs are not in the derived payout sequence");
                    return None;
                }
            }
            last_key = Some(key);
            legs_sats = legs_sats.checked_add(ob.release_sats)?;
            let Some(paid) = leg_paid_sats(ob.release_sats, share) else {
                eprintln!("[btc-payout] ⛔ not signing: a leg's share of the fee is more than half its release, or leaves under dust (A-F35)");
                return None;
            };
            paid_sats = paid_sats.checked_add(paid)?;
            // CACHE-ONLY: the outputs of the Bitcoin transaction this custodian would sign, rebuilt from its own book and
            // chain; the release itself was owed by the cash-out's chain object (checked above: `release_pending`).
            for piece in payout_leg_outputs(paid) {
                outputs.push(TxOut { value_sats: piece, script_pubkey: spk.clone() });
            }
        }
        // A-F21: what the legs' shares may spend on the fee — the whole proposed fee, by construction (`⌈fee / legs⌉` each);
        // the actual fee is held to it below, so the reserve never pays one
        let shares = share.checked_mul(p.legs.len() as u64)?;

        // ⭐ §BR-8 B8-a — the decoy legs: exactly what the decoy rule gives this batch on THIS node's chain, each paid to its
        // validator's custody point; a proposal naming any other decoys is not signed.
        let leg_units: Vec<u64> = p.legs.iter().filter_map(|nf| self.book.obligations.get(nf).and_then(|o| leg_paid_sats(o.release_sats, share))).collect();
        if p.decoys != Self::decoy_plan(node, &leg_units, p.fee_rate, &seed) {
            eprintln!("[btc-payout] not signing: the proposal's decoys are not what the decoy rule gives this batch here (§BR-8)");
            return None;
        }
        let mut decoys: Vec<crate::decoy_tx::DecoyEntry> = Vec::with_capacity(p.decoys.len());
        let mut decoy_sats = 0u64;
        for (vid, sats) in &p.decoys {
            let spk = Self::decoy_spk(node, vid)?;
            decoys.push(crate::decoy_tx::DecoyEntry { vid: *vid, sats: *sats, vout: outputs.len() as u32 });
            outputs.push(TxOut { value_sats: *sats, script_pubkey: spk });
            decoy_sats = decoy_sats.checked_add(*sats)?;
        }

        let mut in_total = 0u64;
        let mut txins: Vec<TxIn> = Vec::with_capacity(p.inputs.len());
        let mut leaves: Vec<(CustodyLeaf, Vec<u8>)> = Vec::with_capacity(p.inputs.len());
        for (i, inp) in p.inputs.iter().enumerate() {
            if p.inputs[..i].iter().any(|x| x.txid == inp.txid && x.vout == inp.vout) {
                return None;
            }
            if self.book.deposits.contains_key(&inp.address) {
                eprintln!("[btc-payout] ⛔ not signing: a co-signed deposit coin is never a payout input — it is swept first (§BR-2)");
                return None;
            }
            let Some(rec) = self.book.addresses.get(&inp.address) else {
                eprintln!("[btc-payout] not signing: an input is at an address this custodian's book does not hold");
                return None;
            };
            let members = self.book.leaves.get(&rec.leaf_hash)?;
            let leaf = Self::leaf_of(members)?;
            if leaf.leaf_hash != rec.leaf_hash {
                return None;
            }
            let out = btc_tx::reserve_output(&leaf, &rec.nonce)?;
            let spk = btc_tx::p2tr_script_pubkey(&out.output_x);
            if btc_tx::reserve_address(hrp, &out.output_x) != inp.address {
                return None;
            }
            let txid_display = btc_tx::txid_display_hex(&inp.txid);
            let Some((value, on_chain_spk)) = src.tx_out(&txid_display, inp.vout) else {
                eprintln!("[btc-payout] not signing: this node's source does not show a proposed input coin");
                return None;
            };
            if value != inp.value_sats || on_chain_spk != spk {
                eprintln!("[btc-payout] ⛔ not signing: a proposed input's value or script is not the coin's");
                return None;
            }
            let coins = src.utxos(&inp.address)?;
            let Some(coin) = coins.iter().find(|c| c.txid == inp.txid && c.vout == inp.vout) else {
                eprintln!("[btc-payout] not signing: a proposed input is not an unspent coin on this node's source");
                return None;
            };
            if !coin.matured() {
                eprintln!("[btc-payout] not signing yet: a proposed input has not matured (F2)");
                return None;
            }
            in_total = in_total.checked_add(value)?;
            txins.push(TxIn { txid: inp.txid, vout: inp.vout, value_sats: value, script_pubkey: spk, sequence: 0xffff_fffd });
            leaves.push((leaf, btc_tx::control_block(&out)));
        }

        let owed = paid_sats.checked_add(decoy_sats)?.checked_add(p.fee_sats)?;
        if in_total < owed {
            eprintln!("[btc-payout] not signing: the inputs do not cover the legs and the fee");
            return None;
        }
        let change_sats = in_total - owed;
        // SAFE AT SCALE, stage three: once the chain records a key for this vault, change returns to that key's HOME
        // address — the one every custodian of the vault derives from the chain — never to an address only this
        // proposal's readers could book
        let (current_leaf, home_nonce) = Self::change_target(node)?;
        if home_nonce.is_some_and(|n| n != p.change_nonce) {
            eprintln!("[btc-payout] ⛔ not signing: the change does not return to the vault's current key's home address");
            return None;
        }
        let change = if change_sats >= DUST_SATS {
            let out = btc_tx::reserve_output(&current_leaf, &p.change_nonce)?;
            outputs.push(TxOut { value_sats: change_sats, script_pubkey: btc_tx::p2tr_script_pubkey(&out.output_x) });
            Some((btc_tx::reserve_address(hrp, &out.output_x), p.change_nonce, current_leaf.leaf_hash))
        } else {
            None
        };
        let tx = Payout { inputs: txins, outputs };
        let mut widest = &leaves[0].0;
        for (l, _) in &leaves {
            if l.slot_keys.len() > widest.slot_keys.len() {
                widest = l;
            }
        }
        let vbytes = tx.estimate_vbytes(widest);
        let Some(own_rate) = src.fee_rate_sat_vb() else {
            eprintln!("[btc-payout] not signing: this node has no fee estimate of its own to judge the proposal's fee against");
            return None;
        };
        let actual_fee = if change.is_some() { p.fee_sats } else { in_total - paid_sats - decoy_sats };
        if actual_fee > shares {
            // a change under dust folds into the fee: the batch's whole fee, not only the proposed one, stays inside its legs'
            // shares (a proposer whose inputs leave such a remainder names it in its fee, so the shares carry it)
            eprintln!("[btc-payout] ⛔ not signing: the batch's actual fee is above its legs' shares of it — the reserve never pays a fee (A-F21)");
            return None;
        }
        if !p.decoys.is_empty() && (p.fee_rate == 0 || p.fee_rate > own_rate.saturating_mul(FEE_CEIL_MULTIPLE)) {
            eprintln!("[btc-payout] ⛔ not signing: the decoys' fee rate is outside [1, {FEE_CEIL_MULTIPLE}× this node's own estimate]");
            return None;
        }
        if actual_fee < vbytes || actual_fee > vbytes.saturating_mul(own_rate).saturating_mul(FEE_CEIL_MULTIPLE) {
            eprintln!("[btc-payout] ⛔ not signing: the fee is outside [1 sat/vB, {FEE_CEIL_MULTIPLE}× this node's own estimate] (F7)");
            return None;
        }
        for nf in &p.legs {
            if let Some(lock) = self.book.locks.get(nf) {
                if lock.proposal_id != *id
                    && !lock.inputs.iter().any(|(t, v)| p.inputs.iter().any(|x| x.txid == *t && x.vout == *v))
                {
                    eprintln!("[btc-payout] ⛔ not signing: this custodian already signed another payout for a leg and this one does not conflict with it (F4)");
                    return None;
                }
            }
        }
        let mut inputs: Vec<InputPlan> = Vec::with_capacity(leaves.len());
        for (i, (leaf, control)) in leaves.into_iter().enumerate() {
            let sighash = tx.sighash_script_path(i, &leaf.leaf_hash)?;
            inputs.push(InputPlan { leaf, control, sighash, depositor_sig: None });
        }
        let decoy_fee_usdm = Self::decoy_fee_usdm(node, decoys.len(), p.fee_rate);
        Some(Plan { tx, inputs, legs_sats, decoys, decoy_fee_usdm, change, rebalance_out: None })
    }

    /// Sign every input whose leaf holds this node's key, lock the legs to this proposal, and return the
    /// signatures to gossip.
    fn sign(&mut self, id: &[u8; 32]) -> Option<PayoutSig> {
        let secret = Self::own_secret()?;
        let signer = btc_tx::xonly_pubkey(&secret)?;
        let slot = self.slots.get_mut(id)?;
        let mut sigs: Vec<Option<[u8; 64]>> = Vec::with_capacity(slot.plan.inputs.len());
        for plan in &slot.plan.inputs {
            if plan.leaf.slot_keys.contains(&signer) {
                let mut aux = blake3::Hasher::new_derive_key("MUSD/btc-payout/aux/v1");
                aux.update(&secret);
                aux.update(&plan.sighash);
                sigs.push(btc_tx::sign_sighash(&secret, &plan.sighash, aux.finalize().as_bytes()));
            } else {
                sigs.push(None);
            }
        }
        slot.sigs.insert(signer, sigs.clone());
        let inputs: Vec<([u8; 32], u32)> = slot.proposal.inputs.iter().map(|i| (i.txid, i.vout)).collect();
        for nf in &slot.proposal.legs {
            self.book.locks.insert(*nf, Lock { proposal_id: *id, inputs: inputs.clone() });
        }
        self.save();
        Some(PayoutSig {
            proposal_id: *id,
            signer,
            sigs: sigs.iter().map(|s| match s { Some(x) => x.to_vec(), None => Vec::new() }).collect(),
        })
    }

    /// A proposal arrived (or this node authored it). `(fresh, messages to gossip)`.
    pub fn on_proposal(&mut self, bytes: &[u8], node: &Node, now_ms: u64) -> (bool, Vec<WireMsg>) {
        let Some(p) = PayoutProposal::decode(bytes) else {
            return (false, Vec::new());
        };
        let Some(id) = p.id() else {
            return (false, Vec::new());
        };
        if self.slots.contains_key(&id) {
            return (false, Vec::new());
        }
        let seated = node.custodian_id().is_some();
        let consolidation = self.is_consolidation(&p);
        if !seated && !(consolidation && self.key_holder(node)) {
            // A non-custodian relays what it cannot judge — ONCE (F347c): it holds no book to judge with, so the
            // record behind its `fresh` is the relay ring, never nothing. A key holder the chain no longer seats
            // judges exactly one kind of proposal: the move of its old key's coins (`key_holder`).
            return (self.first_unjudged_sight(&id), Vec::new());
        }
        // ⭐ SAFE AT SCALE: a proposal by a custodian of ANOTHER vault spends that vault's coins under that vault's leaf —
        // this custodian holds neither its book nor its keys, so it is exactly a node that cannot judge: it relays the
        // proposal once and signs nothing. (Never reached on a one-vault chain: every proposer is in this node's vault.)
        if seated && node.custody_vault_of(&p.proposer).is_some_and(|v| v != node.custody_set_here()) {
            return (self.first_unjudged_sight(&id), Vec::new());
        }
        // A consolidation of coins this node's book does not hold — another vault's, or its own vault's from before it
        // was seated — is likewise one it cannot judge: relayed once, signed by those who hold the old key.
        if consolidation && !self.book.addresses.contains_key(&p.inputs[0].address) {
            return (self.first_unjudged_sight(&id), Vec::new());
        }
        // OWED, the hand-over: a payout of this custodian's own vault names a burn its chain shows owed and it holds no
        // leg for — it asks its vault for that leg (`leg_share_tick`), and judges the proposal's next offer with it.
        if seated {
            for nf in &p.legs {
                self.note_leg_wanted(node, nf, false);
            }
        }
        if self.slots.len() >= PAYOUT_SLOTS_MAX {
            eprintln!("[btc-payout] a proposal arrived while {} are already in flight — judged again when one settles", self.slots.len());
            return (false, Vec::new());
        }
        let Some(src) = btc_source(crate::bridge::btc_net()) else {
            eprintln!("[btc-payout] ⛔ cannot judge a proposal: this custodian has no Bitcoin source to check its coins against");
            return (self.first_unjudged_sight(&id), Vec::new());
        };
        let Some(plan) = self.verify(&p, &id, node, &src) else {
            // ⛔ F347c — REFUSED ON THIS NODE'S OWN CHAIN ⇒ NOT RELAYED. This arm answered `fresh` and recorded
            // nothing, so after a settlement every custodian refused every copy and relayed every copy: the loop
            // [slotF347c] measured (see `unjudged_relayed`). The Monero lane has always had this shape
            // (`xmr_payout::on_payout`: a proposal its own verify refuses is not relayed). Propagation does not
            // need the refuser: the proposer re-offers on its own poll (DB-336), and every custodian that DOES
            // verify it records a slot and relays it once.
            return (false, Vec::new());
        };
        self.slots.insert(id, Slot { proposal: p, plan, sigs: BTreeMap::new(), txid_display: None, raw_hex: None, resent: 0, next_resend_ms: 0 });
        let mut out = Vec::new();
        if let Some(sig) = self.sign(&id) {
            if let Some(bytes) = sig.encode() {
                out.push(WireMsg::PayoutSig(bytes));
            }
            eprintln!("[btc-payout] SIGNED proposal {}… ({} legs, {} inputs) at {now_ms}", h32(&id), self.slots[&id].proposal.legs.len(), self.slots[&id].proposal.inputs.len());
        }
        self.try_broadcast(&id, &src);
        (true, out)
    }

    /// A custodian's signatures arrived. `(fresh, messages to gossip)` — a quorum reached is broadcast to Bitcoin.
    pub fn on_sig(&mut self, bytes: &[u8], node: &Node, _now_ms: u64) -> (bool, Vec<WireMsg>) {
        let Some(s) = PayoutSig::decode(bytes) else {
            return (false, Vec::new());
        };
        let Some(slot) = self.slots.get_mut(&s.proposal_id) else {
            return (false, Vec::new()); // no proposal to verify against — never stored unverified
        };
        if slot.sigs.contains_key(&s.signer) || s.sigs.len() != slot.plan.inputs.len() {
            return (false, Vec::new());
        }
        let mut parsed: Vec<Option<[u8; 64]>> = Vec::with_capacity(s.sigs.len());
        let mut any = false;
        for (i, raw) in s.sigs.iter().enumerate() {
            if raw.is_empty() {
                parsed.push(None);
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(raw.as_slice()) else {
                return (false, Vec::new());
            };
            let plan = &slot.plan.inputs[i];
            if !plan.leaf.slot_keys.contains(&s.signer) || !btc_tx::verify_sighash_sig(&s.signer, &plan.sighash, &sig) {
                return (false, Vec::new()); // a signature that does not verify is not counted, not relayed
            }
            parsed.push(Some(sig));
            any = true;
        }
        if !any {
            return (false, Vec::new());
        }
        slot.sigs.insert(s.signer, parsed);
        if node.custodian_id().is_some() || self.key_holder(node) {
            if let Some(src) = btc_source(crate::bridge::btc_net()) {
                self.try_broadcast(&s.proposal_id, &src);
            }
        }
        (true, Vec::new())
    }

    /// If every input has a quorum of slot signatures, assemble the witness and hand the payout to Bitcoin.
    fn try_broadcast(&mut self, id: &[u8; 32], src: &BtcSource) {
        let Some(slot) = self.slots.get_mut(id) else {
            return;
        };
        if slot.txid_display.is_some() {
            return;
        }
        let mut witnesses: Vec<Vec<Vec<u8>>> = Vec::with_capacity(slot.plan.inputs.len());
        for (i, plan) in slot.plan.inputs.iter().enumerate() {
            let slot_sigs: Vec<Option<[u8; 64]>> = plan
                .leaf
                .slot_keys
                .iter()
                .map(|k| slot.sigs.get(k).and_then(|v| v.get(i).copied().flatten()))
                .collect();
            let Some(mut w) = btc_tx::script_path_witness(&plan.leaf, &slot_sigs, &plan.control) else {
                return; // this input has not reached its quorum yet
            };
            if let Some(dsig) = plan.depositor_sig {
                // §BR-2: the sweep leaf's `<D> CHECKSIGVERIFY` pops the element just under the script first
                let at = w.len() - 2;
                w.insert(at, dsig.to_vec());
            }
            witnesses.push(w);
        }
        let Some(raw) = slot.plan.tx.serialize_with_witness(&witnesses) else {
            return;
        };
        let raw_hex = btc_tx::hex(&raw);
        let txid = btc_tx::txid_display_hex(&slot.plan.tx.txid());
        match src.broadcast(&raw_hex) {
            Some(reported) => eprintln!("[btc-payout] ⭐ PAYOUT BROADCAST {reported} ({} legs, {} sats, {} inputs)", slot.proposal.legs.len(), slot.plan.legs_sats, slot.proposal.inputs.len()),
            None => eprintln!("[btc-payout] the source did not accept the payout broadcast yet — {txid} is fully signed and will be offered again"),
        }
        slot.txid_display = Some(txid);
        slot.raw_hex = Some(raw_hex);
    }

    /// Settle what confirmed, re-offer what is unconfirmed, drop what died (a coin spent by another payout).
    fn settle_or_recover(&mut self, node: &mut Node, src: &BtcSource) {
        let ids: Vec<[u8; 32]> = self.slots.keys().copied().collect();
        for id in ids {
            let txid_bytes = self.slots.get(&id).map(|s| s.plan.tx.txid());
            let (txid, raw, inputs, legs, legs_sats, change) = {
                let Some(slot) = self.slots.get(&id) else {
                    continue;
                };
                (
                    // a slot this custodian signed but never assembled (a peer's signature did not reach it) still knows its
                    // transaction: a taproot txid commits to no witness, so the plan it verified names it. Without this a
                    // signer dropped the slot when its own payout spent the coin, and never booked the change or the swept
                    // reserve coin (MEASURED 2026-11-08, real nodes: the second custodian then refused every payout from
                    // that coin, "an input is at an address this custodian's book does not hold").
                    slot.txid_display.clone().unwrap_or_else(|| btc_tx::txid_display_hex(&slot.plan.tx.txid())),
                    slot.raw_hex.clone(),
                    slot.proposal.inputs.clone(),
                    slot.proposal.legs.clone(),
                    slot.plan.legs_sats,
                    slot.plan.change.clone(),
                )
            };
            match src.tx_confirmations(&txid) {
                Some(confs) if confs >= required_confirmations(legs_sats) => {
                    // spec §3g.1: a rebalance move names its slot, not a burn — nothing to release, and its lock stays
                    // (`rebalance_signed`: this custodian signed a move of that part, so it never signs its cancel).
                    // CACHE-ONLY: the release mirrors what THIS node's own source saw confirm; the burn was applied from
                    // `Class::PegOut` long before, and a rebalance's ledgers move only by `Class::VaultRebalance`.
                    let rebalance = self.slots.get(&id).is_some_and(|s| s.plan.rebalance_out.is_some());
                    // ⭐ A-F114: from the network upgrade the release is a CHAIN object (`Class::ReleaseConfirm`): this
                    // custodian queues its signature over the burns this transaction paid, as its own lane built it
                    if let (false, Some(tb)) = (rebalance, txid_bytes) {
                        let ledger = node.ledger_here(crate::peg::NATIVE_PEG_ASSET_ID);
                        // the deposits this transaction swept: its inputs at a minted deposit's reserve address
                        let swept: Vec<[u8; 32]> = inputs
                            .iter()
                            .map(|i| crate::peg::deposit_id_for_reserve_address(&i.address))
                            .filter(|d| node.peg().deposit_minted(d))
                            .collect();
                        node.queue_own_release(ledger, tb, legs.clone(), swept);
                    }
                    for nf in legs.iter().filter(|_| !rebalance) {
                        let outcome = node.settle_reserve_release_observed(nf);
                        // DB-375: no nullifier beside the payout txid (that pair IS the USDm↔BTC link).
                        eprintln!("[btc-payout] ⭐ SETTLED — payout {txid} at {confs} confirmations ({outcome:?})");
                        self.book.obligations.remove(nf);
                        self.book.locks.remove(nf);
                    }
                    // SAFE AT SCALE, stage three (A-F21): a consolidation's fee left custody — its evidence is kept in
                    // the book's file, before its inputs leave the book, until the chain has booked it
                    // (`cost_evidence` → `Node::own_reserve_cost_sig`; `cost_done`).
                    // CACHE-ONLY: this custodian's own record of a Bitcoin fact; the ledger moves only by the
                    // `Class::ReserveCost` object a block carries.
                    // …and so did a rebalance move's (spec §3g.1), with the part's output beside it so the part is never read as fee
                    let evidence = self.slots.get(&id).filter(|s| self.is_consolidation(&s.proposal) || s.plan.rebalance_out.is_some()).and_then(|s| {
                        let coins: Option<Vec<CoinAddress>> = s.proposal.inputs.iter().map(|i| self.book.addresses.get(&i.address).cloned()).collect();
                        Some((s.plan.tx.txid(), CostEvidence { proposal: s.proposal.encode()?, coins: coins?, rebalance_out: s.plan.rebalance_out.clone() }.encode()))
                    });
                    if let Some((cost_txid, bytes)) = evidence {
                        while self.book.costs.len() >= COSTS_PENDING_MAX {
                            self.book.costs.pop_first();
                        }
                        self.book.costs.insert(cost_txid, bytes);
                    }
                    for inp in &inputs {
                        // §BR-2: the sweep settled — the deposit is a reserve coin now. Any other address may hold more
                        // coins than this payout spent (a key's home is paid by every consolidation and every change):
                        // it leaves the book only once this node's own source shows it empty.
                        if self.book.deposits.remove(&inp.address).is_some() || src.utxos(&inp.address).is_some_and(|c| c.is_empty()) {
                            self.book.addresses.remove(&inp.address);
                        }
                    }
                    if let Some((addr, nonce, leaf_hash)) = change {
                        self.book.addresses.insert(addr, CoinAddress { nonce: nonce.to_vec(), leaf_hash });
                    }
                    self.save();
                    self.slots.remove(&id);
                }
                Some(0) => {
                    if let Some(raw) = raw {
                        let _ = src.broadcast(&raw);
                    }
                }
                Some(_) => {}
                None => {
                    if !Self::inputs_unspent(src, &inputs) {
                        eprintln!("[btc-payout] payout {txid} is unknown to this node's source and a coin it spends is gone — another payout took it; dropping it");
                        self.release_locks_of(&id);
                        self.slots.remove(&id);
                    } else if let Some(raw) = raw {
                        let _ = src.broadcast(&raw);
                    }
                }
            }
        }
    }

    fn inputs_unspent(src: &BtcSource, inputs: &[PayoutInput]) -> bool {
        for inp in inputs {
            let Some(coins) = src.utxos(&inp.address) else {
                return true; // the source did not answer — that is not evidence the coin is gone
            };
            if !coins.iter().any(|c| c.txid == inp.txid && c.vout == inp.vout) {
                return false;
            }
        }
        true
    }

    fn release_locks_of(&mut self, id: &[u8; 32]) {
        let locked: Vec<[u8; 32]> = self.book.locks.iter().filter(|(_, l)| l.proposal_id == *id).map(|(nf, _)| *nf).collect();
        for nf in &locked {
            self.book.locks.remove(nf);
        }
        if !locked.is_empty() {
            self.save();
        }
    }

    /// Whose turn it is to propose: the bonded custodian at `(finalized chain time / slot) mod n`, in sorted-id order.
    fn am_proposer(node: &Node) -> bool {
        let Some(me) = node.custodian_id() else {
            return false;
        };
        // SAFE AT SCALE: the rotation is over THIS custodian's vault (`Node::custody_set_here`: every bonded custodian on a
        // one-vault chain, as it was) — each vault proposes the payouts of its own coins, in its own turn order.
        let ids = node.custody_set_here();
        if ids.is_empty() {
            return false;
        }
        let slot = (node.payout_final_time_ms() / PROPOSER_SLOT_MS) as usize % ids.len();
        ids[slot] == me
    }

    /// Assemble and gossip a proposal for every payable burn not already in flight — the proposer's duty.
    fn propose(&mut self, node: &Node, src: &BtcSource, now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        if !Self::am_proposer(node) {
            return out;
        }
        let net = crate::bridge::btc_net();
        let finalized = node.payout_final_height(); // SPEED L7 + FINALITY OVERLAY (2026-11-17): vote-final OR 64 levels deep (Node::payout_final_height)
        let finalized_ms = node.payout_final_time_ms();
        let epoch = finalized_ms / PROPOSER_SLOT_MS;
        let seed = epoch_seed("BTC", epoch);
        // ⭐ §BR-2 — SWEEP EVERY MINTED CO-SIGNED DEPOSIT FIRST: exactly the transaction its depositor signed, so the coin
        // becomes a single-leaf reserve coin the payouts below can spend, long before its refund leaf opens.
        let in_flight_coins: Vec<([u8; 32], u32)> =
            self.slots.values().flat_map(|s| s.proposal.inputs.iter().map(|i| (i.txid, i.vout))).collect();
        if let Some(me) = node.custodian_id() {
            let deposits: Vec<(String, DepositRec)> = self.book.deposits.iter().map(|(a, r)| (a.clone(), r.clone())).collect();
            for (address, rec) in deposits {
                if in_flight_coins.contains(&(rec.txid, rec.vout))
                    || !node.peg().deposit_minted(&crate::peg::deposit_id_for_reserve_address(&address))
                {
                    continue;
                }
                let Some(coin) = self.book.addresses.get(&address).cloned() else { continue };
                let Some(utxos) = src.utxos(&address) else { continue };
                if !utxos.iter().any(|c| c.txid == rec.txid && c.vout == rec.vout && c.matured()) {
                    continue;
                }
                let proposal = PayoutProposal {
                    asset: "BTC".to_string(),
                    epoch,
                    proposer: me,
                    legs: Vec::new(),
                    inputs: vec![PayoutInput { txid: rec.txid, vout: rec.vout, value_sats: rec.value_sats, address: address.clone() }],
                    fee_sats: rec.fee_sats,
                    change_nonce: btc_tx::sweep_nonce(&coin.nonce),
                    decoys: Vec::new(),
                    fee_rate: 0,
                };
                let Some(bytes) = proposal.encode() else { continue };
                eprintln!("[btc-payout] PROPOSING a co-signed deposit sweep ({} sats, fee {} sats)", rec.value_sats, rec.fee_sats);
                let (fresh, mut sigs) = self.on_proposal(&bytes, node, now_ms);
                if fresh {
                    out.push(WireMsg::PayoutProposal(bytes));
                    out.append(&mut sigs);
                }
            }
        }
        // R7, coins first: a vault whose merge is due is moving its coins to the receiving vault's key — it proposes no
        // cash-out from them (a burn it does not pay is offered to the next vault by the wallet, and settles once there)
        if node.own_vault_coins_leaving() {
            return out;
        }
        let in_flight: Vec<[u8; 32]> = self.slots.values().flat_map(|s| s.proposal.legs.iter().copied()).collect();
        let mut legs: Vec<([u8; 32], u64, u64)> = Vec::new(); // (nf, sats, order key)
        for (nf, ob) in &self.book.obligations {
            if in_flight.contains(nf) || !node.peg().release_pending(nf) || !leg_is_payable(ob, finalized, finalized_ms) {
                continue;
            }
            // CACHE-ONLY: the order key is a pure function of the burn's nullifier and the finalized-height epoch
            // seed — every custodian recomputes the same one; nothing is decided for the chain here.
            match btc_tx::script_pubkey_for_address(&ob.redeem_to) {
                Some((dnet, _)) if dnet == net => legs.push((*nf, ob.release_sats, payout_order_key(nf, &seed))),
                Some(_) => eprintln!("[btc-payout] ⛔ a burn's destination is on another Bitcoin network — it cannot be paid from this reserve"),
                // Monero destinations never reach this book (`absorb` hands them to the Monero lane).
                None => eprintln!("[btc-payout] ⛔ a burn's destination is not a Bitcoin address this lane can pay"),
            }
        }
        if legs.is_empty() {
            return out;
        }
        legs.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
        if legs.len() > BATCH_MAX {
            legs = legs[..BATCH_MAX].to_vec();
        }
        // coins: every matured coin this book knows, locked ones first (a re-proposal must conflict, F4)
        let Some(rate) = src.fee_rate_sat_vb() else {
            eprintln!("[btc-payout] not proposing: no fee estimate from this node's Bitcoin source");
            return out;
        };
        let mut coins: Vec<(PayoutInput, bool)> = Vec::new();
        for address in self.book.addresses.keys() {
            if self.book.deposits.contains_key(address) {
                continue; // §BR-2: a co-signed deposit is swept first, never spent by a payout
            }
            let Some(utxos) = src.utxos(address) else {
                continue;
            };
            for c in utxos {
                // a coin a sweep or a consolidation in flight already spends is not offered to a cash-out as well
                if !c.matured() || in_flight_coins.contains(&(c.txid, c.vout)) {
                    continue;
                }
                let locked = legs.iter().any(|(nf, _, _)| {
                    self.book.locks.get(nf).map(|l| l.inputs.iter().any(|(t, v)| *t == c.txid && *v == c.vout)) == Some(true)
                });
                coins.push((PayoutInput { txid: c.txid, vout: c.vout, value_sats: c.value_sats, address: address.clone() }, locked));
            }
        }
        let Some((leaf, home_nonce)) = Self::change_target(node) else {
            return out;
        };
        // locked coins first (F4); then the coins under the vault's current key, so a cash-out never waits on the
        // signers of a replaced key while the current key holds enough (a replaced key's coins move by consolidation)
        let under_current = |c: &PayoutInput| self.book.addresses.get(&c.address).is_some_and(|a| a.leaf_hash == leaf.leaf_hash);
        coins.sort_by(|a, b| {
            b.1.cmp(&a.1).then(under_current(&b.0).cmp(&under_current(&a.0))).then(a.0.txid.cmp(&b.0.txid)).then(a.0.vout.cmp(&b.0.vout))
        });
        // ⭐ A-F21 / A-F35 — THE BATCH, ITS FEE AND ITS LEGS' EQUAL SHARES, SETTLED TOGETHER. The fee is a function of the batch's
        // inputs and output count; each leg pays its release less `⌈fee / legs⌉`; a leg whose share would pass half its release
        // (or leave under dust) leaves the batch and waits, which raises the others' share; and the decoy rule reads the legs'
        // PAID amounts. So the batch is settled in rounds — each round either final, or one that drops a leg, changes the decoy
        // count the fee was probed with, or takes one more input — at most `legs + inputs + 3` of them (every such change is
        // monotone). The inputs cover every RELEASE in full plus the decoys: the fee is inside the releases, never beside them.
        // CACHE-ONLY: a proposal this custodian forms from its own book, chain and Bitcoin source; every signer recomputes all
        // of it (`verify`), and only the Bitcoin transaction two thirds sign moves a coin.
        let coins: Vec<PayoutInput> = coins.into_iter().map(|(c, _)| c).collect();
        let mut settled: Option<(Vec<PayoutInput>, u64, Vec<([u8; 32], u64)>, u64)> = None; // (inputs, fee, decoys, paid by the legs)
        let (mut decoy_n, mut decoy_sats, mut min_inputs) = (0usize, 0u64, 1usize);
        for _round in 0..legs.len() + PAYOUT_INPUTS_MAX + 3 {
            if legs.is_empty() {
                return out;
            }
            let releases: u64 = legs.iter().map(|l| l.1).fold(0u64, u64::saturating_add);
            let mut chosen: Vec<PayoutInput> = Vec::new();
            let mut in_total = 0u64;
            for c in &coins {
                if chosen.len() >= PAYOUT_INPUTS_MAX || (chosen.len() >= min_inputs && in_total >= releases.saturating_add(decoy_sats)) {
                    break;
                }
                in_total = in_total.saturating_add(c.value_sats);
                chosen.push(c.clone());
            }
            if chosen.len() < min_inputs || in_total < releases.saturating_add(decoy_sats) {
                eprintln!("[btc-payout] not proposing: the matured reserve coins this node sees do not cover the {} legs' {releases} sats", legs.len());
                return out;
            }
            let probe = Payout {
                inputs: chosen.iter().map(|i| TxIn { txid: i.txid, vout: i.vout, value_sats: i.value_sats, script_pubkey: vec![0x51, 0x20], sequence: 0 }).collect(),
                // one output per leg piece, one per decoy, and the change
                outputs: (0..=legs.iter().map(|l| payout_leg_outputs(l.1).len()).sum::<usize>() + decoy_n)
                    .map(|_| TxOut { value_sats: 0, script_pubkey: vec![0u8; 34] })
                    .collect(),
            };
            let fee = probe.estimate_vbytes(&leaf).saturating_mul(rate);
            let Some(share) = leg_fee_share(fee, legs.len()) else {
                return out;
            };
            let before = legs.len();
            legs.retain(|l| leg_paid_sats(l.1, share).is_some());
            if legs.len() != before {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fee, a share and two counts — public on Bitcoin once paid; no address or owner.
                eprintln!(
                    "[btc-payout] {} piece(s) wait: their share of the fee ({share} sats of {fee} at {rate} sat/vB among {before}) is more than half their release, or leaves under dust (A-F35)",
                    before - legs.len()
                );
                continue;
            }
            let leg_units: Vec<u64> = legs.iter().filter_map(|l| leg_paid_sats(l.1, share)).collect();
            // ⭐ §BR-8 B8-a — the decoy rule for this batch over what its legs PAY, priced at this node's rate (every signer
            // recomputes it from the proposal's own fee)
            let decoys = Self::decoy_plan(node, &leg_units, rate, &seed);
            let now_sats: u64 = decoys.iter().map(|d| d.1).fold(0u64, u64::saturating_add);
            if decoys.len() != decoy_n || now_sats > decoy_sats {
                (decoy_n, decoy_sats) = (decoys.len(), now_sats);
                continue; // the fee was probed with another output count, or the inputs were chosen for fewer decoy sats
            }
            let paid: u64 = leg_units.iter().fold(0u64, |a, x| a.saturating_add(*x));
            let spent = paid.saturating_add(now_sats).saturating_add(fee);
            let remainder = in_total.saturating_sub(spent);
            if in_total < spent || (remainder > 0 && remainder < DUST_SATS && in_total > releases.saturating_add(now_sats)) {
                // a remainder under dust would fold into the fee out of the RESERVE's own coins (the inputs exceed the
                // releases): one more input makes it real change; with none left the batch waits for a coin
                min_inputs = chosen.len() + 1;
                continue;
            }
            settled = Some((chosen, fee, decoys, paid));
            break;
        }
        let Some((chosen, fee, decoys, legs_sats)) = settled else {
            eprintln!("[btc-payout] not proposing: the batch did not settle (its fee, its legs' shares and its decoys kept moving)");
            return out;
        };
        let mut cn = blake3::Hasher::new_derive_key("MUSD/btc-payout/change/v1");
        for (nf, _, _) in &legs {
            cn.update(nf);
        }
        for c in &chosen {
            cn.update(&c.txid);
            cn.update(&c.vout.to_le_bytes());
        }
        let Some(me) = node.custodian_id() else {
            return out;
        };
        let proposal = PayoutProposal {
            asset: "BTC".to_string(),
            epoch,
            proposer: me,
            legs: legs.iter().map(|l| l.0).collect(),
            inputs: chosen,
            fee_sats: fee,
            change_nonce: home_nonce.unwrap_or(*cn.finalize().as_bytes()),
            decoys,
            fee_rate: rate,
        };
        let Some(bytes) = proposal.encode() else {
            return out;
        };
        eprintln!("[btc-payout] PROPOSING a payout: {} legs, {legs_sats} sats, fee {fee} sats", proposal.legs.len());
        let (fresh, mut sigs) = self.on_proposal(&bytes, node, now_ms);
        if fresh {
            out.push(WireMsg::PayoutProposal(bytes));
            out.append(&mut sigs);
        }
        out
    }

    /// ⭐ DB-336 — WHAT IS IN FLIGHT IS RE-OFFERED EVERY POLL, NOT GOSSIPED ONCE. For every slot not yet handed to
    /// Bitcoin: its proposal, and `me`'s OWN stored signatures over it, byte-exact (never a new signature).
    ///
    /// MEASURED ([slotB11], two real daemons + a regtest Bitcoin Core, node ea0bdc41, 2026-09-27): both custodians
    /// signed proposal 151c7abb 8 s apart while each writer was shedding pages ("real lane and park are BOTH full"),
    /// and 330 s later neither held the other's signature — broadcast 0 on both. A `PayoutSig` was queued exactly once
    /// (`on_proposal`'s return), so one lost message stranded a 2-of-2 payout for good. The Monero payout lane already
    /// re-sends what is in flight every poll (`xmr_payout.rs`), and the peg lanes re-broadcast every 10 s; this is
    /// that shape. Receivers already dedupe both messages (a known slot makes `on_proposal` not fresh; a known signer
    /// makes `on_sig` not fresh), so a re-offer is never relayed again and nothing amplifies.
    /// Bounded by `PAYOUT_SLOTS_MAX` slots × (one proposal + one signature set) per re-offer, and each slot backs off: its
    /// re-offers wait `PAYOUT_POLL_MS` doubled per re-offer, to 2^`RESEND_BACKOFF_MAX_SHIFT` (BORROWED: TCP's retransmission
    /// backoff, Bitcoin Core's growing rebroadcast interval). Re-offered every poll without end, a few slots that could not
    /// complete filled the cell channel every other message rides (MEASURED 2026-11-08, real nodes: the outbound queue at
    /// 4,068 of its 4,096 bound, 48,629 payout messages refused at it, and the DeFi custodians' engine messages delayed for
    /// minutes behind them).
    fn resend_unfinished(&mut self, me: [u8; 32], now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        for (id, slot) in &mut self.slots {
            if slot.txid_display.is_some() {
                continue; // handed to Bitcoin: settlement reads Bitcoin, the lane has nothing left to agree on
            }
            if now_ms < slot.next_resend_ms {
                continue;
            }
            slot.next_resend_ms = now_ms.saturating_add(PAYOUT_POLL_MS << slot.resent.min(RESEND_BACKOFF_MAX_SHIFT));
            slot.resent = slot.resent.saturating_add(1);
            if let Some(bytes) = slot.proposal.encode() {
                out.push(WireMsg::PayoutProposal(bytes));
            }
            if let Some(mine) = slot.sigs.get(&me) {
                let s = PayoutSig {
                    proposal_id: *id,
                    signer: me,
                    sigs: mine.iter().map(|x| x.map(|b| b.to_vec()).unwrap_or_default()).collect(),
                };
                if let Some(bytes) = s.encode() {
                    out.push(WireMsg::PayoutSig(bytes));
                }
            }
        }
        out
    }

    /// The lane's clock: absorb what the blocks taught, then — on the poll cadence, custodians only — settle,
    /// re-offer, judge solvency and propose.
    pub fn tick(&mut self, node: &mut Node, now_ms: u64) -> Vec<WireMsg> {
        self.refresh_own_point(now_ms);
        self.absorb(node);
        // A custodian the chain seats runs the whole lane. A KEY HOLDER it no longer seats (`key_holder`) runs only what
        // moves its old key's coins: it settles, re-offers and judges consolidations — no epoch share, no payout.
        let seated = node.custodian_id().is_some();
        if !seated && !self.key_holder(node) {
            return Vec::new();
        }
        // §BR-9a step (c): release this custodian's shares of the epoch whose batch has come, and try to open it from what
        // is gathered — before the Bitcoin source gate, so the destinations open on every custodian whether or not this one
        // can reach Bitcoin right now
        let mut released = if seated { self.release_epochs(node, now_ms) } else { Vec::new() };
        if seated {
            if let Some(e) = node.peg().epoch_keys().release_epoch() {
                for p in self.try_open_epoch(node, e) {
                    let _ = node.publish_epoch_fraud(&p);
                }
            }
        }
        if now_ms.saturating_sub(self.last_poll_ms) < PAYOUT_POLL_MS {
            return released;
        }
        self.last_poll_ms = now_ms;
        // spec §3g.1: a vault with nothing of its own yet still looks for a part sent to it
        let part_for_us = seated && node.peg().vault_parts_all().any(|(_, p)| p.into == node.vault_here());
        if self.book.obligations.is_empty() && self.slots.is_empty() && self.book.addresses.is_empty() && !part_for_us {
            return released;
        }
        let Some(src) = btc_source(crate::bridge::btc_net()) else {
            if !self.no_source_said {
                eprintln!("[btc-payout] no private route to Bitcoin (set MONEROUSD_TOR_SOCKS for the onion explorers, or MONEROUSD_BTC_RPC_URL for this machine's Bitcoin Core) — the exit leg waits");
                self.no_source_said = true;
            }
            return released;
        };
        self.no_source_said = false;
        // R3: one fee reading a minute, a day of them — what this node calls a low fee
        // CACHE-ONLY: this node's own readings of a foreign fee market; they decide only what THIS custodian signs.
        if self.fee_ring.is_empty() || now_ms.saturating_sub(self.fee_ring_at_ms) >= FEE_SAMPLE_MS {
            if let Some(rate) = src.fee_rate_sat_vb() {
                self.fee_ring_at_ms = now_ms;
                self.fee_ring.push_back(rate);
                while self.fee_ring.len() > FEE_RING_LEN {
                    self.fee_ring.pop_front();
                }
            }
        }
        // CACHE-ONLY: unchanged by this edit — the lane's own book follows what Bitcoin shows; a release is settled on
        // the chain only by the object its block carries (`Node::settle_reserve_release_observed` reads, never decides).
        self.settle_or_recover(node, &src);
        let ids: Vec<[u8; 32]> = self.slots.keys().copied().collect();
        for id in ids {
            self.try_broadcast(&id, &src);
        }
        self.scan_coins(node, &src);
        if seated {
            self.check_rebalance_arrivals(node, &src);
            // a part's lock outlives its move (the cancel rule reads it) and leaves with the part: a lock that names neither
            // an owed burn nor this vault's part at rest is gone — one at most per part, never a growing set
            let part_id = Self::rebalance_leg_id(node, node.vault_here());
            let before = self.book.locks.len();
            let owed = &self.book.obligations;
            self.book.locks.retain(|nf, _| owed.contains_key(nf) || node.peg().release_pending(nf) || Some(*nf) == part_id);
            if self.book.locks.len() != before {
                self.save();
            }
        }
        // DB-336: re-offer what is in flight first; a fresh proposal from `propose` is gossiped by its own return.
        let mut out = match self.own_point() {
            Some(me) => self.resend_unfinished(me, now_ms),
            None => Vec::new(),
        };
        if seated {
            out.extend(self.propose(node, &src, now_ms));
            out.extend(self.propose_rebalance_move(node, &src, now_ms));
            out.extend(self.coin_share_ask(node, now_ms));
        }
        out.extend(self.propose_consolidation(node, &src, now_ms, node.payout_final_time_ms() / PROPOSER_SLOT_MS));
        released.extend(out);
        released
    }
}

#[cfg(test)]
impl PayoutLane {
    /// TEST — a lane over its own book file (never the operator's).
    pub(crate) fn for_test(book_path: PathBuf) -> Self {
        Self {
            book: CustodyBook::default(),
            book_path,
            slots: BTreeMap::new(),
            foreign: Vec::new(),
            last_poll_ms: 0,
            no_source_said: false,
            unjudged_relayed: std::collections::VecDeque::new(),
            epoch_bundles: BTreeMap::new(),
            epoch_secrets: BTreeMap::new(),
            release_sent_ms: BTreeMap::new(),
            faults_handed: std::collections::BTreeSet::new(),
            window_read: false,
            fee_ring: std::collections::VecDeque::new(),
            fee_ring_at_ms: 0,
            coin_scan: None,
            coin_ask: (0, 0),
            coin_gave: BTreeMap::new(),
            leg_want: BTreeMap::new(),
            leg_gave: BTreeMap::new(),
            own_point: None,
            own_point_tried: false,
            own_point_tried_ms: 0,
            rebalance_seen: std::collections::BTreeSet::new(),
        }
    }
    pub(crate) fn ticket_pending(&self, nf: &[u8; 32]) -> bool {
        self.book.tickets.contains_key(nf)
    }
    /// Book a single-leaf reserve coin address under `members`' leaf, as a minted deposit's sweep or a payout's change
    /// would have: the address it derives.
    pub(crate) fn book_coin_for_test(&mut self, members: &[([u8; 32], u128)], nonce: &[u8]) -> String {
        let leaf = Self::leaf_of(members).expect("the members form a leaf");
        let out = btc_tx::reserve_output(&leaf, nonce).expect("the coin's output derives");
        let address = btc_tx::reserve_address(crate::bridge::btc_net().hrp(), &out.output_x);
        self.book.leaves.insert(leaf.leaf_hash, members.to_vec());
        self.book.addresses.insert(address.clone(), CoinAddress { nonce: nonce.to_vec(), leaf_hash: leaf.leaf_hash });
        address
    }
    pub(crate) fn seed_fee_ring_for_test(&mut self, readings: &[u64]) {
        self.fee_ring = readings.iter().copied().collect();
    }
    pub(crate) fn slot_count_for_test(&self) -> usize {
        self.slots.len()
    }
    pub(crate) fn propose_consolidation_for_test(&mut self, node: &Node, now_ms: u64, epoch: u64) -> Vec<WireMsg> {
        let src = btc_source(crate::bridge::btc_net()).expect("the pin installed a Bitcoin source");
        self.propose_consolidation(node, &src, now_ms, epoch)
    }
    /// The poll's settle step alone, against the pin's installed Bitcoin source.
    /// CACHE-ONLY: the lane's own book follows what its Bitcoin source shows; no chain state is decided here.
    pub(crate) fn settle_for_test(&mut self, node: &mut Node) {
        let src = btc_source(crate::bridge::btc_net()).expect("the pin installed a Bitcoin source");
        self.settle_or_recover(node, &src);
    }
    pub(crate) fn scan_for_test(&mut self, node: &mut Node) -> Option<(std::collections::BTreeSet<[u8; 32]>, u128)> {
        let src = btc_source(crate::bridge::btc_net()).expect("the pin installed a Bitcoin source");
        self.scan_coins(node, &src);
        self.coin_scan.clone()
    }
    pub(crate) fn judge_cost_for_test(&self, evidence: &[u8], node: &Node) -> Option<(u32, u64, [u8; 32])> {
        let src = btc_source(crate::bridge::btc_net()).expect("the pin installed a Bitcoin source");
        self.judge_cost(evidence, node, &src)
    }
    pub(crate) fn book_homes_for_test(&mut self, node: &Node) {
        self.book_key_homes(node);
    }
    /// The destination of the obligation booked for `nf` (BTC book or the Monero hand-over).
    pub(crate) fn obligation_to(&self, nf: &[u8; 32]) -> Option<String> {
        self.book
            .obligations
            .get(nf)
            .map(|o| o.redeem_to.clone())
            .or_else(|| self.foreign.iter().find(|(n, _)| n == nf).map(|(_, o)| o.redeem_to.clone()))
    }
    /// TEST — a ticket as a block's apply hands it to this lane (the burn applied, its leg opened).
    pub(crate) fn insert_ticket_for_test(&mut self, nf: [u8; 32], release_sats: u64, pay_after: u64, ticket: Vec<u8>, epoch_ct: Vec<u8>, redeem_commit: [u8; 32]) {
        self.book.tickets.insert(
            nf,
            PendingTicket { release_sats, burn_height: 1, pay_after, ticket, epoch_ct, redeem_commit, escrow: None, key: None, opened: None, key_known_ms: 0, pieces: Vec::new(), burn_requested_ms: 0 },
        );
        self.try_open_ticket(&nf);
    }
    /// TEST — hold an epoch's key pair as if this lane had opened it, and try every pending ticket.
    pub(crate) fn hold_epoch_for_test(&mut self, e: u64, pk: crate::epoch_key::EpochPublicKey, sk: crate::epoch_key::EpochSecretKey) {
        self.epoch_secrets.insert(e, (pk, sk));
        let pending: Vec<[u8; 32]> = self.book.tickets.iter().filter(|(_, t)| t.opened.is_none()).map(|(nf, _)| *nf).collect();
        for nf in pending {
            self.try_open_ticket(&nf);
        }
    }
    /// The epochs this lane has opened (a pin asserts what each custodian's node holds).
    pub(crate) fn opened_epochs_for_test(&self) -> Vec<u64> {
        self.epoch_secrets.keys().copied().collect()
    }
    pub(crate) fn release_epochs_for_test(&mut self, node: &Node, now_ms: u64) -> Vec<WireMsg> {
        self.release_epochs(node, now_ms)
    }
}

impl Default for PayoutLane {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    /// ⭐ A-F21 / A-F35 PIN — THE RESERVE NEVER PAYS A BITCOIN FEE, AND A LONE PIECE IS PAID. (1) a leg pays its release less
    /// `⌈fee / legs⌉`, the same for every leg of the batch (one rung, one amount inside a batch); (2) a piece whose share is more
    /// than half its release, or leaves under dust, is not paid in that batch; (3) for every batch shape and fee, the coins
    /// that leave custody (what the legs pay plus the fee) never exceed the releases the ledger already debited, and the
    /// difference is under one sat per leg; (4) CALIBRATION, the measured stall: one 13,462-sat piece alone at a fee of 2,626
    /// sats — refused outright by a 2,000-sat allowance — is paid 10,836 here; (5) a fee one sat past the shares is past the
    /// debit, which is exactly what every signer refuses (`verify`: the actual fee is held to `share × legs`).
    #[test]
    fn a_bitcoin_payouts_legs_share_its_fee_equally_and_the_reserve_never_pays() {
        // (1)
        assert_eq!(leg_fee_share(2_626, 1), Some(2_626));
        assert_eq!(leg_fee_share(2_626, 3), Some(876), "the share is rounded up, so the shares always cover the fee");
        assert_eq!(leg_fee_share(0, 4), Some(0));
        assert_eq!(leg_fee_share(1_000, 0), None, "a batch with no leg has no share");
        assert_eq!(leg_paid_sats(100_000, 876), Some(99_124));
        // (2)
        assert_eq!(leg_paid_sats(10_000, 5_000), Some(5_000), "a share of exactly half is carried");
        assert_eq!(leg_paid_sats(10_000, 5_001), None, "⛔ a piece lost more than half to the fee");
        assert_eq!(leg_paid_sats(2 * DUST_SATS - 2, DUST_SATS - 1), None, "⛔ a piece was paid under dust");
        assert_eq!(leg_paid_sats(0, 0), None);
        // (4)
        let share = leg_fee_share(2_626, 1).expect("one leg");
        assert_eq!(leg_paid_sats(13_462, share), Some(10_836), "⛔ the measured lone piece is not paid");
        // (3) and (5), over batch shapes and fees
        for releases in [vec![13_462u64], vec![100_000], vec![100_000, 100_000, 100_000], vec![1_000_000, 50_000, 20_000, 9_000], vec![7_001; 32]] {
            let debited: u64 = releases.iter().sum();
            let n = releases.len();
            for fee in [0u64, 1, 2_626, 2_627, 3_001, 12_345] {
                let share = leg_fee_share(fee, n).expect("legs");
                let Some(paid) = releases.iter().map(|r| leg_paid_sats(*r, share)).sum::<Option<u64>>() else {
                    continue; // a leg that cannot carry this share is left out by the proposer: another batch shape
                };
                assert!(paid + fee <= debited, "⛔⛔ {n} legs, fee {fee}: the batch took {} sats the ledger never debited", paid + fee - debited);
                assert!(debited - paid - fee < n as u64, "the rounding left in the reserve is under one sat per leg");
                assert!(paid + share * n as u64 + 1 > debited, "CALIBRATION: a fee one sat past the shares is past the debit — the refused shape");
            }
        }
    }

    #[test]
    fn a_proposal_and_a_signature_round_trip_their_one_encoding_and_refuse_wider_shapes() {
        let p = PayoutProposal {
            asset: "BTC".into(),
            epoch: 3,
            proposer: [1; 32],
            legs: vec![[2; 32]],
            inputs: vec![PayoutInput { txid: [3; 32], vout: 1, value_sats: 5_000, address: "bcrt1q".into() }],
            fee_sats: 300,
            change_nonce: [4; 32], decoys: Vec::new(), fee_rate: 0 };
        let bytes = p.encode().expect("encodes");
        assert_eq!(PayoutProposal::decode(&bytes).expect("decodes"), p);
        let id = p.id().expect("id");
        let mut p2 = p.clone();
        p2.fee_sats += 1;
        assert_ne!(p2.id().expect("id"), id, "a changed fee is a different proposal");
        // A deposit sweep (no legs, one input) and a consolidation (no legs, one to PAYOUT_INPUTS_MAX inputs) decode — verify
        // judges which it is and whether it is true. A leg-less proposal with decoys does not: decoys ride cash-outs.
        let mut sweep = p.clone();
        sweep.legs = Vec::new();
        assert_eq!(PayoutProposal::decode(&sweep.encode().expect("encodes")).expect("a sweep decodes"), sweep);
        let mut two_in = sweep.clone();
        two_in.inputs.push(PayoutInput { txid: [5; 32], vout: 0, value_sats: 1, address: "bcrt1q".into() });
        assert_eq!(PayoutProposal::decode(&two_in.encode().expect("encodes")).expect("a consolidation decodes"), two_in);
        let mut too_wide = sweep.clone();
        too_wide.inputs = (0..=PAYOUT_INPUTS_MAX as u32).map(|v| PayoutInput { txid: [5; 32], vout: v, value_sats: 1, address: "bcrt1q".into() }).collect();
        assert!(PayoutProposal::decode(&too_wide.encode().expect("encodes")).is_none(), "⛔ a consolidation wider than one transaction's inputs decoded");
        let mut decoyed = sweep.clone();
        decoyed.decoys = vec![([6; 32], 1)];
        assert!(PayoutProposal::decode(&decoyed.encode().expect("encodes")).is_none(), "no legs with decoys is neither a sweep nor a consolidation");
        let mut wide = p.clone();
        wide.legs = vec![[9; 32]; BATCH_MAX + 1];
        assert!(PayoutProposal::decode(&wide.encode().expect("encodes")).is_none(), "wider than a batch is refused");
        let s = PayoutSig { proposal_id: id, signer: [7; 32], sigs: vec![vec![0u8; 64], Vec::new()] };
        assert_eq!(PayoutSig::decode(&s.encode().expect("encodes")).expect("decodes"), s);
        let bad = PayoutSig { proposal_id: id, signer: [7; 32], sigs: vec![vec![0u8; 63]] };
        assert!(PayoutSig::decode(&bad.encode().expect("encodes")).is_none(), "a 63-byte signature is not a signature");
    }

    /// ⭐ F347c — A PROPOSAL THIS NODE CANNOT JUDGE IS RELAYED ONCE, NEVER IN A LOOP.
    ///
    /// MEASURED on real processes ([slotF347c], five nodes): after the burn settled, every custodian refused the
    /// proposal and re-relayed every copy; node3 shed 68,405 Payout cells after the settlement against 11 before it.
    /// The rule: every `fresh` answer is backed by a record. A non-custodian (no book to judge with) answers `fresh`
    /// on the FIRST sight only, and a copy returning through the relay is not fresh. CALIBRATION: a different proposal
    /// is fresh. The ring is bounded: an id pushed out by `PAYOUT_SLOTS_MAX` newer ones relays once more — bounded,
    /// never a loop. (The custodian arm — refused by its own verify ⇒ not relayed — is the one-line `xmr_payout`
    /// shape; its measurement is the next five-node run's post-settlement Payout shed count.)
    #[test]
    fn f347c_a_proposal_this_node_cannot_judge_is_relayed_once_not_in_a_loop() {
        let node = Node::new(crate::block::genesis_block()).expect("a non-custodian node");
        assert!(node.custodian_id().is_none(), "PRECONDITION: this node holds no custodian key");
        let mut lane = PayoutLane::for_test(std::env::temp_dir().join("f347c-this-pin-never-writes-a-book.bin"));
        let proposal = |fee: u64| {
            PayoutProposal {
                asset: "BTC".into(),
                epoch: 3,
                proposer: [1; 32],
                legs: vec![[2; 32]],
                inputs: vec![PayoutInput { txid: [3; 32], vout: 1, value_sats: 5_000, address: "bcrt1q".into() }],
                fee_sats: fee,
                change_nonce: [4; 32], decoys: Vec::new(), fee_rate: 0 }
            .encode()
            .expect("encodes")
        };
        let first = proposal(300);
        assert!(lane.on_proposal(&first, &node, 1).0, "the first sight is relayed");
        for back in 0..8u64 {
            assert!(
                !lane.on_proposal(&first, &node, 2 + back).0,
                "⛔ F347c: a copy that came back through the relay was relayed again — the loop"
            );
        }
        assert!(lane.on_proposal(&proposal(301), &node, 20).0, "CALIBRATION: a different proposal is fresh");
        for fee in 0..PAYOUT_SLOTS_MAX as u64 {
            assert!(lane.on_proposal(&proposal(1_000 + fee), &node, 30).0, "each new proposal relays once");
        }
        assert!(lane.unjudged_relayed.len() <= PAYOUT_SLOTS_MAX, "the ring never grows past its bound");
        assert!(lane.on_proposal(&first, &node, 40).0, "an id pushed out of the ring relays once more — bounded");
        assert!(!lane.on_proposal(&first, &node, 41).0, "…and only once, never in a loop");
    }

    /// ⭐ DB-336 — A SIGNATURE LOST ONCE REACHES THE OTHER CUSTODIAN ON THE NEXT POLL'S RE-OFFER.
    ///
    /// TWO custodian lanes over one 2-of-2 proposal, with real BIP-340 signatures over one sighash. Custodian A signed
    /// and its one gossip was lost; custodian B holds the proposal and its own signature only — exactly the [slotB11]
    /// state (both signed, broadcast 0 on both, 330 s). A's poll re-offers; B must:
    ///   * REFUSE a byte-flipped copy of A's re-offered signature (the re-offer is verified like the first send);
    ///   * ADMIT the genuine re-offer, so B holds both signers = the leaf's k;
    ///   * answer a DUPLICATE re-offer as not fresh, so it is never relayed again (no amplification).
    /// CONTROL: once handed to Bitcoin, A's slot re-offers nothing; a key that never signed re-offers only the proposal.
    /// ⛔ Both lanes are built field by field: `PayoutLane::new` opens the operator's real custody book under HOME, and
    /// nothing in this pin may read or write it.
    #[test]
    fn db336_a_payout_signature_lost_once_reaches_the_other_custodian_on_the_next_polls_reoffer() {
        let (sa, sb) = ([11u8; 32], [22u8; 32]);
        let pa = btc_tx::xonly_pubkey(&sa).expect("custodian A's key");
        let pb = btc_tx::xonly_pubkey(&sb).expect("custodian B's key");
        let leaf = btc_tx::custody_leaf(&[(pa, 1), (pb, 1)]).expect("a two-custodian leaf");
        // `k` counts SLOTS (slots ∝ bond, k = ⌈2Σ/3⌉), so the quorum question is always "how many slots do these
        // signers hold".
        let slots_of = |keys: &[[u8; 32]]| leaf.slot_keys.iter().filter(|k| keys.contains(k)).count() as u32;
        assert!(
            slots_of(&[pa]) < leaf.k && slots_of(&[pb]) < leaf.k && slots_of(&[pa, pb]) >= leaf.k,
            "CALIBRATION: neither custodian alone reaches the leaf's k, both together do — the [slotB11] 2-of-2 shape"
        );
        let sighash = [33u8; 32];
        let sig_a = btc_tx::sign_sighash(&sa, &sighash, &[1u8; 32]).expect("A signs");
        let sig_b = btc_tx::sign_sighash(&sb, &sighash, &[2u8; 32]).expect("B signs");
        let p = PayoutProposal {
            asset: "BTC".into(),
            epoch: 3,
            proposer: pa,
            legs: vec![[2; 32]],
            inputs: vec![PayoutInput { txid: [3; 32], vout: 1, value_sats: 5_000, address: "bcrt1q".into() }],
            fee_sats: 300,
            change_nonce: [4; 32], decoys: Vec::new(), fee_rate: 0 };
        let id = p.id().expect("id");
        let slot = |held: Vec<([u8; 32], [u8; 64])>, broadcast: bool| Slot {
            proposal: p.clone(),
            plan: Plan {
                tx: Payout { inputs: Vec::new(), outputs: Vec::new() },
                inputs: vec![InputPlan { leaf: leaf.clone(), control: Vec::new(), sighash, depositor_sig: None }],
                legs_sats: 5_000,
                decoys: Vec::new(),
                decoy_fee_usdm: 0,
                change: None,
                rebalance_out: None,
            },
            sigs: held.into_iter().map(|(k, s)| (k, vec![Some(s)])).collect(),
            txid_display: broadcast.then(|| "ab".repeat(32)),
            raw_hex: None,
            resent: 0,
            next_resend_ms: 0,
        };
        let lane = |s: Slot, tag: &str| {
            let mut l = PayoutLane::for_test(std::env::temp_dir().join(format!("db336-{tag}-this-pin-never-writes-a-book.bin")));
            l.slots = BTreeMap::from([(id, s)]);
            l
        };
        let node = Node::new(crate::block::genesis_block()).expect("a node for the door's reads");
        let mut lane_a = lane(slot(vec![(pa, sig_a)], false), "a");
        let mut lane_b = lane(slot(vec![(pb, sig_b)], false), "b");
        // A's poll: the re-offer carries the proposal and A's own stored signature, byte-exact.
        let reoffer = lane_a.resend_unfinished(pa, 0);
        let a_sig = reoffer
            .iter()
            .find_map(|m| match m {
                WireMsg::PayoutSig(b) => Some(b.clone()),
                _ => None,
            })
            .expect("A's poll re-offers its own signature");
        let decoded = PayoutSig::decode(&a_sig).expect("the re-offer decodes");
        assert_eq!((decoded.proposal_id, decoded.signer), (id, pa));
        assert_eq!(decoded.sigs, vec![sig_a.to_vec()], "byte-exact: the signature A already made, never a new one");
        assert!(
            reoffer.iter().any(|m| matches!(m, WireMsg::PayoutProposal(b) if PayoutProposal::decode(b).and_then(|q| q.id()) == Some(id))),
            "the unbroadcast proposal rides the re-offer too"
        );
        // TAMPER: a flipped byte in the re-offered signature is refused, and B still lacks A.
        let mut forged = decoded.clone();
        forged.sigs[0][5] ^= 1;
        let (fresh, _) = lane_b.on_sig(&forged.encode().expect("encodes"), &node, 0);
        assert!(!fresh, "a forged re-offer is refused, exactly like a forged first send");
        assert!(!lane_b.slots[&id].sigs.contains_key(&pa), "B holds nothing from the forged copy");
        // THE SECOND PARTY OBSERVES THE EFFECT: B admits A's genuine re-offer and holds the 2-of-2.
        let (fresh, _) = lane_b.on_sig(&a_sig, &node, 0);
        assert!(fresh, "B admits the signature it lost the first time");
        let signers: Vec<[u8; 32]> = lane_b.slots[&id].sigs.keys().copied().collect();
        assert!(slots_of(&signers) >= leaf.k, "B now holds both signers — the slot quorum a broadcast needs");
        // NO AMPLIFICATION: the same re-offer again is not fresh, so B never relays it a second time.
        let (fresh, _) = lane_b.on_sig(&a_sig, &node, 0);
        assert!(!fresh, "a duplicate re-offer is not fresh and is never relayed again");
        // CONTROL: handed to Bitcoin, the slot re-offers nothing.
        assert!(lane(slot(vec![(pa, sig_a)], true), "c").resend_unfinished(pa, 0).is_empty(), "a broadcast payout is not re-offered");
        // BACKOFF: offered again at once, the slot sends nothing; its next re-offer waits one poll (then two, four, ...)
        assert!(lane_a.resend_unfinished(pa, 1).is_empty(), "⛔ a slot was re-offered again before its backoff elapsed");
        // A key that never signed re-offers the proposal only: no signature is invented.
        let unsigned = lane_a.resend_unfinished([9u8; 32], PAYOUT_POLL_MS);
        assert!(
            unsigned.len() == 1 && matches!(unsigned[0], WireMsg::PayoutProposal(_)),
            "no signature is invented for a key that never signed"
        );
    }

    /// §BR-1 — THE SEALED PAY-AFTER IS A PAYOUT BOUND: a piece whose burn finalized is still neither proposed nor signed
    /// before its pay-after height finalizes (the one rule both callers read), and the bound survives the book's file
    /// encoding. RED-first on the 2026-10-28 tree without the field: every finalized burn paid at the next slot.
    #[test]
    fn br1_a_piece_is_neither_proposed_nor_signed_before_its_sealed_pay_after() {
        let ob = Obligation { release_sats: 1_000_000, redeem_to: "bcrt1p".into(), burn_height: 100, pay_after: 5_000 };
        assert!(!leg_is_payable(&ob, 99, 5_000), "the burn itself is not finalized: not payable (F1)");
        assert!(!leg_is_payable(&ob, 100, 4_999), "⛔ §BR-1: the burn finalized but the sealed pay-after has not — payable too early");
        assert!(leg_is_payable(&ob, 100, 5_000), "at its pay-after time the piece is payable");
        let fast = Obligation { pay_after: 0, ..ob.clone() };
        assert!(leg_is_payable(&fast, 100, 0), "a zero pay-after (the fast switch) is payable the moment the burn finalizes");
        let mut b = CustodyBook::default();
        b.obligations.insert([7; 32], ob.clone());
        let back: CustodyBook = postcard::from_bytes(&postcard::to_allocvec(&b).expect("encodes")).expect("decodes");
        assert_eq!(back.obligations[&[7; 32]].pay_after, 5_000, "the bound rides the book's file encoding");
        // the denomination rule the executor and every attestor apply to a piece
        assert!(crate::peg_pool::is_denom(ob.release_sats), "CALIBRATION: the piece is a ladder unit");
        assert!(!crate::peg_pool::is_denom(ob.release_sats + 1), "an odd release is not a piece");
    }

    /// ⛔ THE KEY FILE IS NEVER READ ON THE TICK PATH. A custodian's Bitcoin secret is read through the keystore, and a
    /// sealed keystore pays a key derivation per read; 7217023e derived this node's custody point from it on every
    /// runtime loop (`absorb`). The lane now keeps the PUBLIC point: derived once, tried again at most once per poll
    /// while the key file does not answer, and every reader on the tick path reads the lane's copy.
    // TWO-PARTY-REVIEWED: one process's own read cadence of its own key file — there is no second party to this
    // property; what the point is used for across custodians is pinned in `node::vault_pins`.
    #[test]
    fn a_custodians_point_is_derived_at_most_once_a_poll_and_read_from_the_lane_on_the_tick_path() {
        let mut lane = PayoutLane::for_test(std::env::temp_dir().join("own-point-this-pin-never-writes-a-book.bin"));
        assert_eq!((lane.own_point(), lane.own_point_tried), (None, false), "a fresh lane has read nothing");
        lane.refresh_own_point(1_000);
        assert!(lane.own_point_tried && lane.own_point_tried_ms == 1_000, "the first poll tries the key file");
        let first = lane.own_point;
        lane.refresh_own_point(1_000 + PAYOUT_POLL_MS - 1);
        assert_eq!(lane.own_point_tried_ms, 1_000, "⛔ the key file was read again inside one poll");
        lane.refresh_own_point(1_000 + PAYOUT_POLL_MS);
        // with a key the point is kept and never derived again; without one the next poll tries once more
        assert_eq!(lane.own_point_tried_ms, if first.is_some() { 1_000 } else { 1_000 + PAYOUT_POLL_MS });
        assert_eq!(lane.own_point(), first, "the lane's copy is what every reader on the tick path sees");
    }

    #[test]
    fn the_custody_book_round_trips_through_its_file_encoding() {
        let mut b = CustodyBook::default();
        b.obligations.insert([1; 32], Obligation { release_sats: 10, redeem_to: "bcrt1q".into(), burn_height: 5, pay_after: 0 });
        b.locks.insert([1; 32], Lock { proposal_id: [2; 32], inputs: vec![([3; 32], 0)] });
        b.addresses.insert("bcrt1p".into(), CoinAddress { nonce: vec![4u8; 64], leaf_hash: [5; 32] });
        b.leaves.insert([5; 32], vec![([6; 32], 1)]);
        let bytes = postcard::to_allocvec(&b).expect("encodes");
        let back: CustodyBook = postcard::from_bytes(&bytes).expect("decodes");
        assert_eq!(back.obligations, b.obligations);
        assert_eq!(back.locks, b.locks);
        assert_eq!(back.addresses, b.addresses);
        assert_eq!(back.leaves, b.leaves);
    }
}

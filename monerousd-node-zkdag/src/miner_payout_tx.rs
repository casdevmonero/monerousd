// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ §BR-11 — THE MINER POOL'S CONSTANT PER-BLOCK PAYOUT (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §9, §16).
//!
//! The miner share of every protocol fee (§BR-14's 10 %) accrues in the peg ledger's miner pool; the fold step that closes a
//! quarter fixes the next quarter's per-block rate (`PegLedger::miner_quarter_roll`), and each block may carry ONE
//! `chain_object::Class::MinerPayout` paying exactly that rate to its producer's own key. Mining stays paid after the block
//! reward ends, and nothing is minted: every payout is fee USDm already in the pool.
//!
//! The object is the SAT reward's public-opening shape (Zcash ZIP-213's shielded coinbase) with the USDm asset tag: every node
//! recomputes `cm = asset_note_cm(amount, USDm, o)` from the object's own public opening, so no mint carrier is needed, and the
//! note spends only with its owner's `(ask, nk)` (DB-395). §9.6 checklist:
//! 1 work — it rides a block whose header grind the block door verified; 2 proof — the commitment is RECOMPUTED from public
//! data (`credit_is_authorised`), at admission and at the fold; 3 value — the fold pays only the open quarter's rate, from
//! the pool, never more than the pool holds (`PegLedger::pay_miner_payout`); 4 replay — `payout_nf(cm)` rides the block's
//! lane and the spent set refuses a copied payout; 5 bounded work — one note, one Poseidon2 evaluation, one per block;
//! 6 parity with `Class::SatoshiReward` — the same door shape, the same one-per-block rule, the same parent key.

use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// One block's miner-pool payout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerPayoutTx {
    /// The carrying block's PARENT KEY (the largest blue score among its parents) — the key its quarter is read from, the
    /// same key the block's SAT reward states.
    pub key: u64,
    /// The open quarter's per-block rate, in USDm atomic units (judged against the folded state at the fold).
    pub amount: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — ONE note, `cover::PQ_NOTE_BYTES` whole or
    /// `chain_object::NOTE_REF_BYTES` in carriage form (decode refuses any other width).
    pub note: Vec<u8>,
    /// The note's PUBLIC opening `o = P(spk ‖ s)` (canonical 32-byte digest form), as the SAT reward's.
    pub opening: [u8; 32],
    /// The note's owner as an OLI clue under the operator wallet's reward locator key (the `"sat"` domain, next index).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `peg_in_tx::OWNER_CLUE_MAX` — decode refuses wider.
    pub owner_clue: Vec<u8>,
}

/// The credit-set frame bytes a block's payout carriage can take at most (the whole note, its public fields and the length
/// prefix) — reserved beside the reward's, as Bitcoin Core's `BlockAssembler` reserves the coinbase's space.
pub const PAYOUT_FRAME_RESERVE: usize = crate::satoshi::REWARD_FRAME_RESERVE;

/// The payout period ("quarter") chain tick `tick` falls in, for a period of `quarter_ticks` ticks
/// (`ChainParams::miner_quarter_keys`, a week of ticks by default). ⭐ A-F60: a block's period is read from its PARENT-KEY
/// BLOCK's chain tick (`Node::payout_quarter_of`) — a time, so "one week" is a week at any real block rate; it was the parent
/// key itself (a blue score), a week only at the target pace. The parent-key block is fixed by the parents alone, so a
/// producer knows its block's period before it seals the payout.
#[must_use]
pub fn quarter_of(tick: u64, quarter_ticks: u64) -> u64 {
    tick / quarter_ticks.max(1)
}

/// The payout's one-time id: the spent set refuses a second object naming the same note (as `satoshi::reward_nf`).
#[must_use]
pub fn payout_nf(note_cm: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"MONEROUSD-MINER-PAYOUT-NF-v1");
    pre.extend_from_slice(note_cm);
    crate::cover::canonical_tag_of_hash(Hash32::hash(&pre).as_bytes())
}

impl MinerPayoutTx {
    /// The canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }

    /// Refuses rather than guesses: a wrong-width note, an empty or oversized clue, a non-canonical opening or a zero amount
    /// is not a payout. (The amount against the open quarter's rate is a state question, judged at the fold.)
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<MinerPayoutTx> {
        let p: MinerPayoutTx = crate::chain_object::decode_exact(bytes)?;
        let width_ok = p.note.len() == crate::cover::PQ_NOTE_BYTES || p.note.len() == crate::chain_object::NOTE_REF_BYTES;
        if !width_ok
            || p.owner_clue.is_empty()
            || p.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
            || crate::spend_frontier::cm_bytes_to_root(&p.opening).is_none()
            || p.amount == 0
        {
            return None;
        }
        Some(p)
    }

    /// The framed chain object.
    #[must_use]
    pub fn to_object(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::MinerPayout, &self.encode())
    }

    /// The note's commitment bytes (the canonical 32-byte prefix every note carries).
    #[must_use]
    pub fn note_cm(&self) -> Option<[u8; 32]> {
        self.note.get(..32)?.try_into().ok()
    }

    /// The no-over-pay / no-wrong-asset gate, by RECOMPUTATION: the note's commitment must be `asset_note_cm(amount, USDm, o)`
    /// for the object's own public opening — a note opening to more, to another asset or under another owner than the
    /// object states is refused, at admission and at the fold, on every node alike.
    #[must_use]
    pub fn credit_is_authorised(&self) -> bool {
        let (Some(cm), Some(o)) =
            (crate::spend_frontier::note_cm_of(&self.note), crate::spend_frontier::cm_bytes_to_root(&self.opening))
        else {
            return false;
        };
        usdm_decider::whir_rec_block::asset_note_cm(self.amount, usdm_decider::whir_rec_block::USDM_ASSET_TAG, o) == cm
    }

    /// The payout a producer lays for the block's parent `key`: `amount` (the open quarter's rate) SEALED to the operator
    /// wallet's scan key and spend key, filed under the reward locator's `index` (the wallet's `"sat"` sweep finds it).
    /// `seal_seed` is `None` in production (OS entropy); a test passes its reproducible block context.
    #[must_use]
    pub fn seal(
        recipient: &crate::satoshi::RewardRecipient,
        index: u64,
        key: u64,
        amount: u64,
        seal_seed: Option<[u8; 32]>,
    ) -> Option<MinerPayoutTx> {
        if amount == 0 {
            return None;
        }
        let (note, opening) = crate::faucet::seal_asset_note(
            &recipient.scan_ek,
            &recipient.spk,
            amount,
            usdm_decider::whir_rec_block::USDM_ASSET_TAG,
            seal_seed,
        )?;
        let p = MinerPayoutTx {
            key,
            amount,
            note: note.to_vec(),
            opening: crate::spend_frontier::leaf_to_cm_bytes(opening),
            owner_clue: crate::satoshi::reward_clue(&recipient.sat_loc_sk, index),
        };
        p.credit_is_authorised().then_some(p)
    }
}

/// A payout's stated key is in force when it is at or below the carrying block's parent key. The period it is paid in is
/// the CARRYING block's (`Node::payout_quarter_of` of its parents, A-F60) and the amount must be that open period's rate
/// (`PegLedger::pay_miner_payout`), so the key's exact value moves nothing else (`satoshi::reward_key_in_force`, same
/// reason): an older key reaches no other period's rate.
#[must_use]
pub fn payout_key_in_force(stated: u64, parent_key: Option<u64>) -> bool {
    parent_key.is_some_and(|k| stated <= k)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object opens its own note, decodes back to itself, and every tamper of the binding is refused by recomputation.
    #[test]
    fn br11_a_payout_opens_its_own_note_and_a_tampered_one_is_refused() {
        let (rc, _dk) = crate::satoshi::RewardRecipient::for_test(&[0xB1; 32]);
        let p = MinerPayoutTx::seal(&rc, 3, 9, 2_500, Some([0x11; 32])).expect("a payout seals");
        assert!(p.credit_is_authorised(), "the payout opens its own note");
        assert_eq!(MinerPayoutTx::decode(&p.encode()).as_ref(), Some(&p), "one encoding");
        let mut more = p.clone();
        more.amount += 1;
        assert!(!more.credit_is_authorised(), "TAMPER: an amount the note does not hold");
        let mut other = p.clone();
        other.opening = crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]));
        assert!(!other.credit_is_authorised(), "TAMPER: another owner's opening");
        let mut zero = p.clone();
        zero.amount = 0;
        assert!(MinerPayoutTx::decode(&zero.encode()).is_none(), "a zero payout is not a payout");
        assert!(MinerPayoutTx::seal(&rc, 3, 9, 0, None).is_none(), "nothing seals for a zero rate");
        assert_eq!(quarter_of(31, 16), 1, "the period is the tick's index at the period length");
        // CHAIN-OBJECT: the `Class::MinerPayout` object's stated key against its carrying block's parent key (a pure rule)
        assert!(payout_key_in_force(9, Some(9)) && payout_key_in_force(8, Some(9)), "a key at or below the parent key is in force");
        // CHAIN-OBJECT: the same rule, refusing — a key past the carrying block's parent key, or a block with none
        assert!(!payout_key_in_force(10, Some(9)) && !payout_key_in_force(0, None), "⛔ a key past the parent key, or no parent key, was in force");
    }
}

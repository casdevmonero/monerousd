// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A-F114 — A PAYOUT'S RELEASE, AS A CHAIN OBJECT (docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md, "The confirmed-release
//! chain object"). INCREMENT 1 of its build: the type, its one encoding and its signed statement. It is not framed as a
//! `chain_object::Class` yet, and no door or signer reads it, so nothing on today's chain changes.
//!
//! WHY IT EXISTS: `PegLedger::spent_burns` minus `released` is the book of OWED releases (a burn whose foreign payout has not
//! happened). Kept whole, it grows with every cash-out ever (the spent-set class). The `released` mark is set from THIS
//! node's own Bitcoin source (`Node::settle_reserve_release_observed`, CACHE-ONLY), so it cannot take a burn out of consensus
//! state. A release must therefore be a chain object every node folds alike. `ReserveCost` is not it: it books consolidation,
//! sweep and rebalance fees, never a payout (a payout's fee rides its burn's allowance, A-F21).
//!
//! THE OBJECT: custody's threshold over "foreign transaction `txid` of `ledger` paid the burns `released`". A custodian signs
//! it only when its OWN payout lane built `txid` from exactly those owed releases and its OWN source shows the transaction
//! final (`btc_watch::required_confirmations`); a signer signs only the statement its own node derived (Bybit 2025). At its
//! fold every named burn must be OWED, or the object is refused whole; the fold then takes each out of `spent_burns` on every
//! node alike, so the owed book holds only what is still unpaid.
//!
//! §9.6: (1) the carrying block's PoW and the object's stamp; (2) the threshold of the paying vault's custodians over
//! [`release_statement`]; (3) creates no value: it only REMOVES owed entries, and an entry it names that is not owed refuses
//! it; (4) replay: inside the window its one-time id [`ReleaseConfirmTx::one_time_id`], past it the owed book itself (a
//! replay names burns no longer owed); (5) bounded: at most [`MAX_RELEASED`] burns; (6) parity with `ReserveCost`'s door:
//! the same vault threshold (`PegLedger::burn_signed`), the same per-foreign-transaction id; (7) SCALE: one vault's
//! signatures and `MAX_RELEASED` ids, whatever the bonded set or the height; (8) AI RESISTANT: (c) the custody threshold,
//! the same trust the payout itself rests on (≥ 2/3 can move the reserve), bounded by the owed book: it can only remove a
//! burn that was owed, never pay one.

use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};


/// The most burns one payout transaction may release: the payout lane's batch bound.
pub const MAX_RELEASED: usize = 256;

/// The most signatures a release carries: the chain's one attestor ceiling.
pub const MAX_RELEASE_ATTESTORS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;

/// One payout's release: the vault ledger, the foreign transaction, the burns it paid (sorted, distinct), and the custody
/// signatures over [`release_statement`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseConfirmTx {
    pub ledger: u32,
    pub txid: [u8; 32],
    pub released: Vec<[u8; 32]>,
    /// ⭐ A-F114 — the DEPOSIT ids this foreign transaction SWEPT into the reserve (a consolidation's inputs, each a minted
    /// deposit's reserve address, `peg::deposit_id_for_reserve_address`): at the fold each leaves the minted-deposit book
    /// (`PegLedger::confidential_deposit_ids`), which then holds a deposit only from its mint to its sweep. After the sweep
    /// its coins have left the address, so no honest custodian attests a second mint against it (`btc_watch::deposit_confirmed`
    /// reads unspent coins), and a NEW deposit to that address mints again (it used to be refused as already minted).
    /// Sorted, distinct, at most [`MAX_RELEASED`].
    pub swept: Vec<[u8; 32]>,
    /// The signatures as raw `(pubkey, sig)` pairs, as `ReserveCost` carries them (`MintAttestor` has no serde form).
    pub attestors: Vec<(Vec<u8>, Vec<u8>)>,
}

/// What custody signs: the ledger, the foreign transaction and the burns it paid, under a domain of its own.
#[must_use]
pub fn release_statement(ledger: u32, txid: &[u8; 32], released: &[[u8; 32]], swept: &[[u8; 32]]) -> Vec<u8> {
    let mut m = crate::pqauth::node_statement(b"musdm.peg.release-confirm.v1");
    m.extend_from_slice(&ledger.to_le_bytes());
    m.extend_from_slice(txid);
    for list in [released, swept] {
        m.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for id in list {
            m.extend_from_slice(id);
        }
    }
    m
}

/// One id list as the object holds it: sorted, distinct, at most [`MAX_RELEASED`].
fn list_ok(v: &[[u8; 32]]) -> bool {
    v.windows(2).all(|w| w[0] < w[1]) && v.len() <= MAX_RELEASED
}

impl ReleaseConfirmTx {
    /// The one encoding (an encoding failure is empty bytes, which no reader decodes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Strict decode: one canonical encoding, the burns sorted and distinct and at most [`MAX_RELEASED`], at least one
    /// burn, and the signatures within their ceiling.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        (list_ok(&t.released)
            && list_ok(&t.swept)
            && !(t.released.is_empty() && t.swept.is_empty())
            && t.attestors.len() <= MAX_RELEASE_ATTESTORS)
            .then_some(t)
    }

    /// The statement its signatures cover.
    #[must_use]
    pub fn statement(&self) -> Vec<u8> {
        release_statement(self.ledger, &self.txid, &self.released, &self.swept)
    }

    /// The framed object bytes (`Class::ReleaseConfirm`).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::ReleaseConfirm, &self.encode())
    }

    /// Wrap this object as the transaction that carries it into a block: no note; its lane (the one-time id, cover-padded)
    /// is laid by the publisher (`Node::publish_release_confirm` → `Node::lay_object_lane`), as a cost's is. The stamp is
    /// ground as a real submit grinds it.
    #[must_use]
    pub fn as_pq_tx(&self, stamp_bits: u32) -> crate::mempool::PqTx {
        let blob = self.wire();
        let mut tx = crate::mempool::PqTx {
            clock_ms: 0,
            id: crate::mempool::PqTx::content_id(&blob),
            weight: blob.len() as u32,
            blob,
            nullifiers: Vec::new(),
            pow_stamp: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            output_notes: Vec::new(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: Vec::new(),
            nullifier_absence: Vec::new(),
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        let mut s = 0u64;
        loop {
            tx.pow_stamp = s;
            if tx.stamp_work() >= stamp_bits {
                break;
            }
            s = s.wrapping_add(1);
        }
        tx
    }

    /// The signatures as the shared tally reads them.
    #[must_use]
    pub fn attestors(&self) -> Vec<MintAttestor> {
        self.attestors.iter().map(|(pubkey, sig)| MintAttestor { pubkey: pubkey.clone(), sig: sig.clone() }).collect()
    }

    /// Its one-time id: one release per `(ledger, txid)`.
    #[must_use]
    pub fn one_time_id(&self) -> [u8; 32] {
        let mut key = b"musdm.peg.release-confirm.key.v1".to_vec();
        key.extend_from_slice(&self.ledger.to_le_bytes());
        key.extend_from_slice(&self.txid);
        *blake3::hash(&key).as_bytes()
    }
}

/// ONE custodian's signature over a release, gossiped until the vault's threshold has signed (increment 4 of the build).
/// §9.6: (1) the lane's admission stamp on the wire; (2) the signer's ML-DSA over [`release_statement`] this node forms;
/// (3) no value moves (the fold decides); (4) a repeat is not new; (5) one verify, a book bounded per release
/// (`Node::RELEASE_BOOK_MAX`); (6) parity with `ReserveCostSig`; (7) SCALE: one entry per signer per release, a vault's
/// signers; (8) a persuasive release gains nothing: a custodian signs only burns ITS OWN payout lane paid, and every
/// gatherer counts a signature only for burns its own owed book still holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSig {
    pub ledger: u32,
    pub txid: [u8; 32],
    pub released: Vec<[u8; 32]>,
    pub swept: Vec<[u8; 32]>,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl ReleaseSig {
    /// The one wire encoding (an encoding failure is empty bytes, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Strict decode: the burns sorted, distinct, at most [`MAX_RELEASED`], and the ML-DSA ceilings.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: Self = crate::chain_object::decode_exact(bytes)?;
        (list_ok(&s.released)
            && list_ok(&s.swept)
            && !(s.released.is_empty() && s.swept.is_empty())
            && !s.pubkey.is_empty()
            && !s.sig.is_empty()
            && s.pubkey.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX
            && s.sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX)
            .then_some(s)
    }
}

// TWO-PARTY-REVIEWED: this module is one object's encoding and statement, a pure function of its bytes with no second side
// yet. The cross-party claim (two nodes fold one release and agree on the owed book) is the fold's, pinned in node/pins.rs
// in the increment that frames the class and wires its door.
#[cfg(test)]
mod tests {
    use super::*;

    /// One encoding: a release round-trips, and an unsorted, repeated, empty or oversized burn list is refused.
    #[test]
    fn a_release_has_one_encoding_and_refuses_an_unsorted_or_empty_list() {
        let ok = ReleaseConfirmTx { ledger: 1, txid: [7; 32], released: vec![[1; 32], [2; 32]], swept: Vec::new(), attestors: Vec::new() };
        assert_eq!(ReleaseConfirmTx::decode(&ok.encode()), Some(ok.clone()));
        let unsorted = ReleaseConfirmTx { released: vec![[2; 32], [1; 32]], ..ok.clone() };
        assert_eq!(ReleaseConfirmTx::decode(&unsorted.encode()), None);
        let repeated = ReleaseConfirmTx { released: vec![[1; 32], [1; 32]], ..ok.clone() };
        assert_eq!(ReleaseConfirmTx::decode(&repeated.encode()), None);
        let empty = ReleaseConfirmTx { released: Vec::new(), ..ok.clone() };
        assert_eq!(ReleaseConfirmTx::decode(&empty.encode()), None);
        let sweep_only = ReleaseConfirmTx { released: Vec::new(), swept: vec![[9; 32]], ..ok.clone() };
        assert_eq!(ReleaseConfirmTx::decode(&sweep_only.encode()), Some(sweep_only.clone()), "a sweep alone is one release");
        let unsorted_sweep = ReleaseConfirmTx { swept: vec![[9; 32], [8; 32]], ..ok.clone() };
        assert_eq!(ReleaseConfirmTx::decode(&unsorted_sweep.encode()), None);
        assert_ne!(sweep_only.statement(), empty.statement(), "the statement binds the swept deposits");
        let big = ReleaseConfirmTx {
            released: (0..=MAX_RELEASED as u32)
                .map(|i| {
                    let mut a = [0u8; 32];
                    a[..4].copy_from_slice(&i.to_be_bytes());
                    a
                })
                .collect(),
            ..ok.clone()
        };
        assert_eq!(ReleaseConfirmTx::decode(&big.encode()), None);
        assert_ne!(ok.statement(), unsorted.statement(), "the statement binds the burns");
    }
}

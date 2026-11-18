// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ SAFE AT SCALE — `Class::ReserveCost`: A VAULT'S RESERVE FALLS BY THE FEE ITS CUSTODY PAID A FOREIGN CHAIN TO MOVE
//! THE VAULT'S OWN COINS (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3d, finding A-F21).
//!
//! When a vault's members change, its Monero wallet and its Bitcoin leaf are re-keyed and its coins swept to the new
//! keys; when a vault merges, its coins are swept to the receiving vault's. Each sweep pays a miner fee out of the
//! coins it moves, and nobody is charged for it (a cash-out's fee is the redeemer's; a deposit's sweep fee is the
//! depositor's). Unbooked, the vault's coins stand below its ledger's reserve by that fee for good, and every
//! custodian's own solvency hold then refuses the vault's next deposit. So the fee is booked: one object per foreign
//! transaction lowers the vault's reserve by that transaction's PUBLIC fee.
//!
//! The object: the vault's ledger, the fee (public on its own chain), the foreign transaction, the reserve after, the
//! proof that the reserve after plus the fee is the reserve the chain holds, a bound proof past a small floor, and the
//! signatures of two thirds of that vault. Everything that decides it lives in `PegLedger::check_reserve_cost` /
//! `reserve_cost` (its §9.6 answers are there); this module is the one encoding and the one seam from a block's bytes
//! to that door.
//!
//! BORROWED: THORChain books the gas its vaults spend on outbound and migration transactions against the pool they
//! moved (the reserve reimburses); a one-time id per foreign transaction in the spent set (Zcash nullifiers, as a
//! deposit's id already is).
//! SCALE: one vault's signatures (sixteen at most on a chain of more than one vault), two proofs, one object per
//! foreign transaction — nothing grows with the bonded set or with height.
//! cons: the fee is paid by the vault's collateral, not by whoever caused the re-key — the reserve falls and the
//! supply does not, so the vault's ratio falls by the fee over its reserve (order 10^-5 for an ordinary sweep); one
//! more proof-carrying object per sweep (the sum proof, about 125 KB as measured on the ride's).

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The most signatures a cost carries: the chain's one attestor ceiling (a one-vault chain's whole set signs it).
pub const MAX_COST_ATTESTORS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;

/// What a cost names: the vault ledger, the public fee in the foreign chain's atoms, the foreign transaction whose fee
/// it is, and the ledger's reserve commitment after.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCostHeader {
    pub ledger: u32,
    pub cost: u64,
    pub txid: [u8; 32],
    pub post_reserve: crate::spend_frontier::Digest4,
}

/// The EXACT payload type this class's bytes deserialize to: the header, the sum proof, the bound proof (empty at or
/// under the floor) and the attestations as raw `(pubkey, sig)` pairs.
pub type ReserveCostPayload = (ReserveCostHeader, Vec<u8>, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// A cost as its parts: what the door reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveCost {
    pub header: ReserveCostHeader,
    pub sum: Vec<u8>,
    pub bound: Vec<u8>,
    pub attestors: Vec<MintAttestor>,
}

impl ReserveCost {
    /// The canonical payload bytes (unframed). An encode failure yields EMPTY bytes, which no reader decodes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let att: Vec<(Vec<u8>, Vec<u8>)> = self.attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect();
        postcard::to_stdvec(&(self.header, self.sum.clone(), self.bound.clone(), att)).unwrap_or_default()
    }

    /// The ONE wire encoding: the canonical payload framed under its own class.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        frame(Class::ReserveCost, &self.encode())
    }

    /// The one-time id this object retires (`chain_object::object_own_nullifiers`): its ledger and foreign transaction.
    #[must_use]
    pub fn one_time_id(&self) -> [u8; 32] {
        crate::peg::one_time_id_nf(crate::peg::ONE_TIME_RESERVE_COST, &crate::peg::PegLedger::reserve_cost_key(self.header.ledger, &self.header.txid))
    }

    /// Wrap this object as the transaction that carries it into a block: no note. Its lane — the one-time id above,
    /// cover-padded to the constant width with the lane evidence every tag carries — is laid by the publisher
    /// (`Node::publish_reserve_cost` → `Node::lay_object_lane`, the one helper every object publisher shares), so the
    /// spent set refuses a second object for the same foreign transaction. The anti-spam stamp is ground as a real
    /// submit grinds it.
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
}

/// THE ONE DECODE, and the one place this class's bounds live: strict full consumption; a bridge ledger's id (a coin
/// ledger books no cost); a fee above zero; a sum proof inside the decider's bound; a bound proof that is empty exactly
/// when the fee is at or under the ledger's floor; one to `MAX_COST_ATTESTORS` attestations inside the ML-DSA ceilings.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<ReserveCost> {
    let (header, sum, bound, pairs) = decode_exact::<ReserveCostPayload>(payload)?;
    let floor = crate::peg::PegLedger::reserve_cost_floor(header.ledger)?;
    let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
    if header.cost == 0 || sum.is_empty() || sum.len() > max || bound.len() > max || (header.cost <= floor) != bound.is_empty() {
        return None;
    }
    if pairs.is_empty()
        || pairs.len() > MAX_COST_ATTESTORS
        || pairs.iter().any(|(pk, sig)| pk.is_empty() || sig.is_empty() || pk.len() > crate::peg_attest::PEG_ATTEST_PUBKEY_MAX || sig.len() > crate::peg_attest::PEG_ATTEST_SIG_MAX)
    {
        return None;
    }
    let attestors = pairs.into_iter().map(|(pubkey, sig)| MintAttestor { pubkey, sig }).collect();
    Some(ReserveCost { header, sum, bound, attestors })
}

/// The widest evidence a cost signature carries: one consolidation proposal of `PAYOUT_INPUTS_MAX` inputs (each a
/// txid, an index, a value and an address of at most 90 characters) is under 4 KB in its one encoding.
pub const COST_EVIDENCE_MAX: usize = 4_096;

/// ⭐ SAFE AT SCALE, stage three — ONE CUSTODIAN'S SIGNATURE OVER A RESERVE COST OF ITS OWN VAULT
/// (`WireMsg::ReserveCostSig`), in the key lane's shape (`vault_key_tx::VaultKeySig`): each custodian of the ledger's
/// vault signs alone, after ITS OWN source shows the foreign transaction moving the vault's coins to the vault's own
/// key at that fee, the header ITS OWN opening derives (the reserve after, under the blind every custodian of the
/// vault derives). `evidence` is the move itself — the consolidation proposal — so a custodian that never saw the
/// proposal (it joined after, or was down) can judge the same cost from its own source and add its signature. The
/// receiver forms the signed message from its own chain's pair; a custodian holding two thirds of the vault proves
/// the fall from its own opening and frames the object.
/// §9.6 (a gossip door): (1) no PoW — a relay cache; (2) the signer's ML-DSA signature over the message the receiver
/// forms; (3) no value moves — the door at the fold decides; (4) a repeat is not new; (5) one signature verify, a book
/// bounded per signer; (6) parity with `VaultKeySig`; (7) scale — one entry per signer per cost, a vault's signers;
/// (8) a persuasive header gains nothing: a custodian signs only what its own source and opening derive, and the
/// evidence is re-judged, never believed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCostSig {
    pub header: ReserveCostHeader,
    pub evidence: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl ReserveCostSig {
    /// The one wire encoding (an encoding failure is an empty vector, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Strict full-consumption decode: a bridge ledger's id, a fee above zero, evidence inside its bound, the ML-DSA
    /// ceilings.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: ReserveCostSig = decode_exact(bytes)?;
        crate::peg::PegLedger::reserve_cost_floor(s.header.ledger)?;
        (s.header.cost > 0
            && !s.evidence.is_empty()
            && s.evidence.len() <= COST_EVIDENCE_MAX
            && !s.pubkey.is_empty()
            && !s.sig.is_empty()
            && s.pubkey.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX
            && s.sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX)
            .then_some(s)
    }
}

/// What applying a block-carried cost did on this node.
#[derive(Debug, PartialEq, Eq)]
pub enum CostApply {
    /// The blob is not a cost (another class, or out of bounds): nothing was touched.
    NotCost,
    /// The door applied it: the ledger's reserve stands on the stated commitment.
    Booked,
    /// The door refused it: nothing was touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> crate::spend_frontier::Digest4 {
        crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(b)).unwrap()
    }

    fn smallest() -> ReserveCost {
        ReserveCost {
            header: ReserveCostHeader { ledger: crate::peg::NATIVE_PEG_ASSET_ID, cost: 1_200, txid: [7u8; 32], post_reserve: d(1) },
            sum: vec![3u8; 8],
            bound: Vec::new(),
            attestors: vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }],
        }
    }

    /// The codec alone: one encoding round-trips, and every out-of-bounds shape is refused at the decode (the door
    /// behind it is pinned on two parties in `peg::tests` and across nodes in `node::vault_pins`).
    // TWO-PARTY-REVIEWED: a codec bound has one endpoint by nature; the second endpoint of this class — a peer's own
    // ledger judging and applying the bytes — is `peg::tests::safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum`.
    #[test]
    fn a_cost_has_one_encoding_and_every_out_of_bounds_shape_is_refused_at_the_decode() {
        let c = smallest();
        let wire_bytes = c.wire();
        let (class, payload) = unframe(&wire_bytes).expect("framed");
        assert_eq!(class, Class::ReserveCost, "it frames under its own class");
        let back = decode(payload).expect("the smallest cost decodes");
        assert_eq!(back, c);
        assert_eq!(back.encode(), payload, "one encoding: decode then encode is the same bytes");
        let refused = |c: &ReserveCost| decode(&c.encode()).is_none();
        let mut tail = payload.to_vec();
        tail.push(0);
        assert!(decode(&tail).is_none(), "⛔ a trailing byte was read as a cost");
        let on = |ledger: u32| ReserveCost { header: ReserveCostHeader { ledger, ..c.header }, ..c.clone() };
        assert!(!refused(&on(crate::peg::vault_ledger(3, crate::peg::XMR_PEG_ASSET_ID))), "a higher vault's Monero ledger books a cost");
        assert!(refused(&on(crate::peg::COIN_BTC_ASSET_ID)), "⛔ a coin ledger booked a cost (Bitcoin's custody books it on the bridge ledger)");
        assert!(refused(&on(7)), "⛔ a registered wrapped asset booked a custody cost");
        assert!(refused(&on(crate::peg::VAULT_LEDGER_BIT | 0xff)), "⛔ a malformed ledger id booked a cost");
        assert!(refused(&ReserveCost { header: ReserveCostHeader { cost: 0, ..c.header }, ..c.clone() }), "⛔ a cost of nothing decoded");
        assert!(refused(&ReserveCost { sum: Vec::new(), ..c.clone() }), "⛔ a cost with no sum proof decoded");
        assert!(refused(&ReserveCost { sum: vec![0u8; crate::solvency::SolvencyProof::MAX_PROOF_BYTES + 1], ..c.clone() }), "⛔ a proof past the decider's bound decoded");
        let floor = crate::peg::PegLedger::reserve_cost_floor(crate::peg::NATIVE_PEG_ASSET_ID).expect("Bitcoin has a floor");
        assert!(refused(&ReserveCost { bound: vec![9u8; 8], ..c.clone() }), "⛔ a bound proof rode a cost under the floor (two encodings of one cost)");
        let past = ReserveCost { header: ReserveCostHeader { cost: floor + 1, ..c.header }, ..c.clone() };
        assert!(refused(&past), "⛔ a cost past the floor decoded with no bound proof");
        assert!(!refused(&ReserveCost { bound: vec![9u8; 8], ..past }), "a cost past the floor decodes with its bound proof");
        assert!(refused(&ReserveCost { attestors: Vec::new(), ..c.clone() }), "⛔ a cost nobody signed decoded");
        assert!(refused(&ReserveCost { attestors: vec![c.attestors[0].clone(); MAX_COST_ATTESTORS + 1], ..c.clone() }), "⛔ more signatures than the chain's ceiling decoded");
        // THE COST LANE'S SIGNATURE MESSAGE: one encoding, and every out-of-bounds shape refused at its decode
        let s = ReserveCostSig { header: c.header, evidence: vec![5u8; 64], pubkey: vec![1u8; 4], sig: vec![2u8; 4] };
        assert_eq!(ReserveCostSig::decode(&s.wire()), Some(s.clone()));
        let off = |s: &ReserveCostSig| ReserveCostSig::decode(&s.wire()).is_none();
        let mut tail = s.wire();
        tail.push(0);
        assert!(ReserveCostSig::decode(&tail).is_none(), "⛔ a trailing byte was read as a cost signature");
        assert!(off(&ReserveCostSig { header: ReserveCostHeader { ledger: crate::peg::COIN_BTC_ASSET_ID, ..c.header }, ..s.clone() }), "⛔ a cost signature named a ledger that books no cost");
        assert!(off(&ReserveCostSig { header: ReserveCostHeader { cost: 0, ..c.header }, ..s.clone() }), "⛔ a signature over a cost of nothing decoded");
        assert!(off(&ReserveCostSig { evidence: Vec::new(), ..s.clone() }), "⛔ a cost signature with no evidence decoded");
        assert!(off(&ReserveCostSig { evidence: vec![0u8; COST_EVIDENCE_MAX + 1], ..s.clone() }), "⛔ evidence past its bound decoded");
        assert!(off(&ReserveCostSig { sig: Vec::new(), ..s.clone() }) && off(&ReserveCostSig { pubkey: Vec::new(), ..s.clone() }), "⛔ an unsigned cost signature decoded");
        assert!(off(&ReserveCostSig { sig: vec![0u8; crate::peg_attest::PEG_ATTEST_SIG_MAX + 1], ..s }), "⛔ a signature past the ML-DSA ceiling decoded");
        // the one-time id is the ledger and the foreign transaction, nothing else
        assert_eq!(c.one_time_id(), ReserveCost { header: ReserveCostHeader { cost: 9, post_reserve: d(2), ..c.header }, ..c.clone() }.one_time_id(), "a second booking of one foreign transaction retires the same id");
        assert_ne!(c.one_time_id(), on(crate::peg::XMR_PEG_ASSET_ID).one_time_id());
    }
}

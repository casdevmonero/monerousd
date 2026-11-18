// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ SAFE AT SCALE, stage three — `Class::VaultRebalance`: PART OF ONE CUSTODY VAULT'S LEDGERS MOVES TO ANOTHER VAULT,
//! IN THREE STEPS (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3g.1).
//!
//! A deposit is never refused (user 2026-10-24), so a vault can be signed past what its own bonds repay by the whole
//! bonded set. That state must not rest: the excess moves, by proof, to a vault that has room. A merge moves a thin
//! vault's WHOLE ledgers; this class moves a PART of a vault's ledgers, whatever the vault's strength.
//!
//! One class, three kinds, each signed by ONE vault — the vault whose own opening and own source show what the step
//! says — and one slot of chain state per giving vault (`PegLedger::vault_parts`):
//!   • CARVE (the giver): per ledger kind the part and the giver's pair after, `after + part = now` proven for both
//!     words; the part rests in the giver's slot. `PegLedger::check_vault_carve`.
//!   • TAKE (the receiver, once its own source shows the part's coins): per kind its pair after, `now + part = after`
//!     proven over the SLOT'S commitment, and its bound proof after (`peg::VaultRide`) or, with none, two thirds of
//!     the whole bonded weight. The slot closes. `PegLedger::check_vault_take`.
//!   • CANCEL (the giver, for a part nobody took, one rotation day after its carve): per kind its pair after,
//!     `now + part = after`. The slot closes. `PegLedger::check_vault_cancel`.
//! Why three: one object naming both vaults' pairs needs the coins moved first, and a vault past its bound is a busy
//! one — its pair moves within the hour a Bitcoin move confirms, the statement no longer forms, and the coins already
//! sent no longer match the part. Here the ledger entry comes first, the coins are derived from the slot, and each
//! vault races only its own deposits. Everything that decides a step lives in the three doors (their §9.6 answers are
//! there); this module is the one encoding and the one seam from a block's bytes to those doors.
//!
//! BORROWED: THORChain's vault migration (the old vault's outbound is its debit, the new vault's observed inbound is
//! its credit); IBC (escrow on the source, then mint on the destination); this chain's own merge object.
//! SCALE: one vault's signers per step whatever the bonded set — at most sixteen signatures and two sum proofs per
//! ledger kind (the kinds are the protocol's list `peg::CUSTODY_LEDGER_KINDS`), and the take's ride. Without a bound
//! proof the whole bonded set's two thirds sign the take (`MAX_SIGS`).
//! cons: two proofs a kind and step (about 165 KB each as measured on the ride's): a carve and a take of both bridge
//! kinds are about 0.7 MB each. The whole-set path of the take is not fixed-size.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The most signatures a step carries: the chain's one attestor ceiling, reached only by a take with no bound proof.
pub const MAX_SIGS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;

/// Which step a rebalance object is, and the vault whose slot it opens or closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultRebalanceHeader {
    /// The giving vault takes a part out of its ledgers for vault `into`.
    Carve { from: u32, into: u32 },
    /// The vault that `from`'s slot is for adds the part to its own ledgers.
    Take { from: u32 },
    /// The giving vault adds its own slot's part back to its ledgers.
    Cancel { from: u32 },
}

impl VaultRebalanceHeader {
    /// The giving vault: the one whose slot the step opens or closes.
    #[must_use]
    pub fn from(&self) -> u32 {
        match self {
            Self::Carve { from, .. } | Self::Take { from } | Self::Cancel { from } => *from,
        }
    }
}

/// The EXACT payload type this class's bytes deserialize to: the step; one leg per ledger kind, in ascending kind
/// order; the ride bytes (a take's bound proof, else empty); then the attestations as raw `(pubkey, sig)` pairs.
pub type VaultRebalancePayload = (VaultRebalanceHeader, Vec<crate::peg::RebalanceLeg>, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// A rebalance step as its parts: what the doors read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRebalance {
    pub header: VaultRebalanceHeader,
    /// O1-FOOTPRINT-REVIEWED: at most one per entry of `peg::CUSTODY_LEDGER_KINDS` (`decode`), each proof under the decider's bound.
    pub legs: Vec<crate::peg::RebalanceLeg>,
    pub ride: Vec<u8>,
    pub sigs: Vec<MintAttestor>,
}

fn pairs_of(attestors: &[MintAttestor]) -> Vec<(Vec<u8>, Vec<u8>)> {
    attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect()
}

impl VaultRebalance {
    /// The canonical payload bytes (unframed). An encode failure yields EMPTY bytes, which no reader decodes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(&(self.header, self.legs.clone(), self.ride.clone(), pairs_of(&self.sigs))).unwrap_or_default()
    }

    /// The ONE wire encoding: the canonical payload framed under its own class.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        frame(Class::VaultRebalance, &self.encode())
    }

    /// Wrap this object as the transaction that carries it into a block — the merge's own publisher shape
    /// (`vault_merge_tx::VaultMerge::as_pq_tx`): it mints nothing and burns nothing, so every note, nullifier and
    /// witness list is empty, which is what `chain_object::wrapper_binds_object` requires for a class that names no
    /// note. The anti-spam stamp is ground as a real submit grinds it: 2^stamp_bits expected tries.
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

fn key_in_bounds(pk: &[u8], sig: &[u8]) -> bool {
    !pk.is_empty() && !sig.is_empty() && pk.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX
}

fn header_in_bounds(h: &VaultRebalanceHeader) -> bool {
    match h {
        VaultRebalanceHeader::Carve { from, into } => from != into && *from <= crate::peg::VAULT_INDEX_MAX && *into <= crate::peg::VAULT_INDEX_MAX,
        VaultRebalanceHeader::Take { from } | VaultRebalanceHeader::Cancel { from } => *from <= crate::peg::VAULT_INDEX_MAX,
    }
}

/// THE ONE DECODE, and the one place this class's bounds live: strict full consumption; vault indexes inside the
/// chain's bound, a carve's two vaults distinct; legs in their one order (`PegLedger::rebalance_legs_in_order`), each
/// with both proofs and none past the decider's proof bound, STATING ITS PART IF AND ONLY IF THE STEP IS A CARVE; ride
/// bytes that are empty or a bound proof, and empty unless the step is a take; one to `MAX_SIGS` signatures inside the
/// ML-DSA ceilings.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<VaultRebalance> {
    let (header, legs, ride, sigs) = decode_exact::<VaultRebalancePayload>(payload)?;
    if !header_in_bounds(&header) || !crate::peg::PegLedger::rebalance_legs_in_order(&legs) {
        return None;
    }
    let carve = matches!(header, VaultRebalanceHeader::Carve { .. });
    let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
    if legs.iter().any(|l| l.part.is_some() != carve || l.reserve_sum.is_empty() || l.minted_sum.is_empty() || l.reserve_sum.len() > max || l.minted_sum.len() > max) {
        return None;
    }
    if !ride.is_empty() && (!matches!(header, VaultRebalanceHeader::Take { .. }) || !crate::peg::VaultRide::decode(&ride).is_some_and(|r| r.by_vault())) {
        return None; // one encoding: a take's bound proof, or no ride bytes at all
    }
    if sigs.is_empty() || sigs.len() > MAX_SIGS || !sigs.iter().all(|(pk, sig)| key_in_bounds(pk, sig)) {
        return None;
    }
    Some(VaultRebalance { header, legs, ride, sigs: sigs.into_iter().map(|(pubkey, sig)| MintAttestor { pubkey, sig }).collect() })
}

/// What one custodian's lane signature is over (`VaultRebalanceSig`): a step of the object above, or the receiving
/// vault's CONSENT — a lane statement no object carries (`PegLedger::vault_part_consent_msg`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebalanceStatement {
    /// The giving vault's carve for vault `into`: per kind the part and its pair after.
    Carve {
        from: u32,
        into: u32,
        /// O1-FOOTPRINT-REVIEWED: at most one per entry of `peg::CUSTODY_LEDGER_KINDS` (`VaultRebalanceSig::decode`).
        posts: Vec<crate::peg::RebalancePost>,
    },
    /// The receiving vault's consent to be sent the coins of `from`'s slot, at its key recorded since `key_since_tick`.
    Consent { from: u32, key_since_tick: u64 },
    /// The receiving vault's take of `from`'s slot: per kind its pair after.
    Take { from: u32, posts: Vec<crate::peg::RebalancePost> },
    /// The giving vault's cancel of its own slot: per kind its pair after.
    Cancel { from: u32, posts: Vec<crate::peg::RebalancePost> },
}

impl RebalanceStatement {
    /// The giving vault the statement is about.
    #[must_use]
    pub fn from(&self) -> u32 {
        match self {
            Self::Carve { from, .. } | Self::Consent { from, .. } | Self::Take { from, .. } | Self::Cancel { from, .. } => *from,
        }
    }

    /// The statement's identity in the signature book.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("musdm.vault-rebalance.statement.v1");
        h.update(&postcard::to_stdvec(self).unwrap_or_default());
        *h.finalize().as_bytes()
    }

    fn in_bounds(&self) -> bool {
        let kinds = crate::peg::CUSTODY_LEDGER_KINDS;
        let posts_ok = |posts: &[crate::peg::RebalancePost], carve: bool| {
            !posts.is_empty() && posts.len() <= kinds.len() && posts.iter().all(|(a, part, _)| kinds.contains(a) && part.is_some() == carve) && posts.windows(2).all(|w| w[0].0 < w[1].0)
        };
        let vault_ok = |v: u32| v <= crate::peg::VAULT_INDEX_MAX;
        match self {
            Self::Carve { from, into, posts } => from != into && vault_ok(*from) && vault_ok(*into) && posts_ok(posts, true),
            Self::Consent { from, .. } => vault_ok(*from),
            Self::Take { from, posts } | Self::Cancel { from, posts } => vault_ok(*from) && posts_ok(posts, false),
        }
    }
}

/// ⭐ SAFE AT SCALE, stage three (spec §3g.1) — ONE CUSTODIAN'S SIGNATURE OVER A STATEMENT OF A REBALANCE
/// (`WireMsg::VaultRebalanceSig`), in the merge lane's shape. The receiver forms the signed message from ITS OWN chain
/// (`PegLedger::vault_carve_msg` / `vault_part_consent_msg` / `vault_take_msg` / `vault_cancel_msg`), so a signature
/// over another pre-state or another slot verifies under nothing, and it counts the signer only when its own chain
/// seats that signer in the vault the statement is that vault's to make.
/// §9.6 (a gossip door): (1) no PoW — a relay cache; (2) the signer's ML-DSA signature over the message the receiver
/// forms; (3) no value moves — the doors at the fold decide, with their sum proofs; a consent moves no ledger at all;
/// (4) a repeat is not new; (5) one signature verify, a book bounded per signer and vault; (6) parity with
/// `VaultMergeSig`; (7) scale — one vault's signers per statement (and the whole set's for a take with no bound
/// proof, only while the set fits the object: `MAX_SIGS`); (8) a persuasive message gains nothing: every statement is
/// each signer's own derivation from its own chain, openings and sources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRebalanceSig {
    pub stmt: RebalanceStatement,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl VaultRebalanceSig {
    /// The one wire encoding (an encoding failure is an empty vector, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Strict full-consumption decode: vault indexes inside the chain's bound; a statement's pairs in the one order a
    /// step carries its legs, a part stated by a carve and by no other; the ML-DSA ceilings.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: VaultRebalanceSig = decode_exact(bytes)?;
        (s.stmt.in_bounds() && key_in_bounds(&s.pubkey, &s.sig)).then_some(s)
    }
}

/// What applying a block-carried rebalance step did on this node.
#[derive(Debug, PartialEq, Eq)]
pub enum RebalanceApply {
    /// The blob is not a rebalance (another class, or out of bounds): nothing was touched.
    NotRebalance,
    /// The door applied it: the step's ledgers stand on the pairs after and the slot opened or closed.
    Moved,
    /// The door refused it: nothing was touched.
    Refused(crate::peg::PegOutcome),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> crate::spend_frontier::Digest4 {
        crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(b)).unwrap()
    }

    fn leg(asset: u32, carve: bool) -> crate::peg::RebalanceLeg {
        crate::peg::RebalanceLeg { asset, part: carve.then(|| (d(1), d(2))), post: (d(3), d(4)), reserve_sum: vec![3u8; 8], minted_sum: vec![4u8; 8] }
    }

    fn smallest() -> VaultRebalance {
        VaultRebalance {
            header: VaultRebalanceHeader::Carve { from: 1, into: 0 },
            legs: vec![leg(crate::peg::NATIVE_PEG_ASSET_ID, true)],
            ride: Vec::new(),
            sigs: vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }],
        }
    }

    /// The codec alone: one encoding round-trips for each step, and every out-of-bounds shape is refused at the decode
    /// (the doors behind it are pinned across two parties in
    /// `peg::tests::safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_and_nothing_is_created`).
    // TWO-PARTY-REVIEWED: a codec bound has one endpoint by nature; the doors' second endpoint is the peer ledger of the pin named above.
    #[test]
    fn a_rebalance_has_one_encoding_and_every_out_of_bounds_shape_is_refused_at_the_decode() {
        let m = smallest();
        let wire_bytes = m.wire();
        let (class, payload) = unframe(&wire_bytes).expect("framed");
        assert_eq!(class, Class::VaultRebalance, "it frames under its own class");
        let back = decode(payload).expect("the smallest carve decodes");
        assert_eq!(back, m);
        assert_eq!(back.encode(), payload, "one encoding: decode then encode is the same bytes");
        let native = crate::peg::NATIVE_PEG_ASSET_ID;
        let take = VaultRebalance { header: VaultRebalanceHeader::Take { from: 1 }, legs: vec![leg(native, false)], ..m.clone() };
        let cancel = VaultRebalance { header: VaultRebalanceHeader::Cancel { from: 1 }, legs: vec![leg(native, false)], ..m.clone() };
        assert_eq!(decode(&take.encode()), Some(take.clone()), "a take decodes");
        assert_eq!(decode(&cancel.encode()), Some(cancel.clone()), "a cancel decodes");

        let refused = |m: &VaultRebalance| decode(&m.encode()).is_none();
        let mut tail = payload.to_vec();
        tail.push(0);
        assert!(decode(&tail).is_none(), "⛔ a trailing byte was read as a rebalance");
        assert!(refused(&VaultRebalance { header: VaultRebalanceHeader::Carve { from: 1, into: 1 }, ..m.clone() }), "⛔ a vault carved a part for itself");
        assert!(refused(&VaultRebalance { header: VaultRebalanceHeader::Carve { from: crate::peg::VAULT_INDEX_MAX + 1, into: 0 }, ..m.clone() }), "⛔ a vault index outside the chain's bound decoded");
        assert!(refused(&VaultRebalance { header: VaultRebalanceHeader::Take { from: crate::peg::VAULT_INDEX_MAX + 1 }, ..take.clone() }), "⛔ a take of a slot outside the chain's bound decoded");
        // a part is stated by a carve and by no other step: one encoding of each
        assert!(refused(&VaultRebalance { legs: vec![leg(native, false)], ..m.clone() }), "⛔ a carve that states no part decoded");
        assert!(refused(&VaultRebalance { legs: vec![leg(native, true)], ..take.clone() }), "⛔ a take that states a part of its own decoded");
        assert!(refused(&VaultRebalance { legs: vec![leg(native, true)], ..cancel.clone() }), "⛔ a cancel that states a part of its own decoded");
        let kinds = crate::peg::CUSTODY_LEDGER_KINDS;
        let widest = VaultRebalance { legs: kinds.iter().map(|a| leg(*a, true)).collect(), ..m.clone() };
        assert_eq!(decode(&widest.encode()), Some(widest.clone()), "a carve of every ledger kind the chain lists decodes");
        let mut past = widest.clone();
        past.legs.push(leg(kinds[kinds.len() - 1] + 1, true));
        assert!(refused(&past), "⛔ a leg for a kind outside the list decoded");
        assert!(refused(&VaultRebalance { legs: vec![leg(kinds[0], true), leg(kinds[0], true)], ..m.clone() }), "⛔ one ledger kind twice decoded");
        assert!(refused(&VaultRebalance { legs: vec![leg(kinds[1], true), leg(kinds[0], true)], ..m.clone() }), "⛔ a second order of the same legs decoded");
        for strip in 0..2 {
            let mut missing = m.clone();
            let l = &mut missing.legs[0];
            [&mut l.reserve_sum, &mut l.minted_sum][strip].clear();
            assert!(refused(&missing), "⛔ a leg with proof {strip} of its two missing decoded");
        }
        let mut wide = m.clone();
        wide.legs[0].reserve_sum = vec![0u8; crate::solvency::SolvencyProof::MAX_PROOF_BYTES + 1];
        assert!(refused(&wide), "⛔ a proof past the decider's bound decoded");
        assert!(refused(&VaultRebalance { legs: Vec::new(), ..m.clone() }), "⛔ a step that moves nothing decoded");
        assert!(refused(&VaultRebalance { sigs: Vec::new(), ..m.clone() }), "⛔ a step nobody signed decoded");
        assert!(refused(&VaultRebalance { sigs: vec![m.sigs[0].clone(); MAX_SIGS + 1], ..m.clone() }), "⛔ more signatures than the chain's ceiling decoded");
        assert!(refused(&VaultRebalance { ride: crate::peg::VaultRide::of(3).encode(), ..take.clone() }), "⛔ a ride with no proofs decoded");
        assert!(refused(&VaultRebalance { ride: vec![7u8; 5], ..take.clone() }), "⛔ junk ride bytes decoded");
        let ride = crate::peg::VaultRide { vault: 0, sum_commit: d(5), sum: vec![1u8; 8], bound: vec![2u8; 8] };
        assert!(!refused(&VaultRebalance { ride: ride.encode(), ..take }), "a take under its bound proof decodes");
        assert!(refused(&VaultRebalance { ride: ride.encode(), ..m.clone() }), "⛔ a carve carrying a bound proof decoded (the bound is the take's)");
        assert!(refused(&VaultRebalance { ride: ride.encode(), ..cancel }), "⛔ a cancel carrying a bound proof decoded");

        // the lane signature: one encoding, and the same shape rules for the statement it names
        let posts = |carve: bool| vec![(native, carve.then(|| (d(1), d(2))), (d(3), d(4)))];
        let sig = |stmt: RebalanceStatement| VaultRebalanceSig { stmt, pubkey: vec![1u8; 4], sig: vec![2u8; 4] };
        for s in [
            sig(RebalanceStatement::Carve { from: 1, into: 0, posts: posts(true) }),
            sig(RebalanceStatement::Consent { from: 1, key_since_tick: 9 }),
            sig(RebalanceStatement::Take { from: 1, posts: posts(false) }),
            sig(RebalanceStatement::Cancel { from: 1, posts: posts(false) }),
        ] {
            assert_eq!(VaultRebalanceSig::decode(&s.wire()), Some(s.clone()), "a lane signature decodes to itself");
        }
        assert!(VaultRebalanceSig::decode(&sig(RebalanceStatement::Carve { from: 1, into: 0, posts: posts(false) }).wire()).is_none(), "⛔ a carve statement with no part decoded");
        assert!(VaultRebalanceSig::decode(&sig(RebalanceStatement::Take { from: 1, posts: posts(true) }).wire()).is_none(), "⛔ a take statement with a part decoded");
        assert!(VaultRebalanceSig::decode(&sig(RebalanceStatement::Carve { from: 1, into: 1, posts: posts(true) }).wire()).is_none(), "⛔ a carve statement for the giver itself decoded");
        assert!(VaultRebalanceSig::decode(&sig(RebalanceStatement::Cancel { from: 1, posts: Vec::new() }).wire()).is_none(), "⛔ a cancel statement of no ledger decoded");
        assert_ne!(
            RebalanceStatement::Take { from: 1, posts: posts(false) }.digest(),
            RebalanceStatement::Cancel { from: 1, posts: posts(false) }.digest(),
            "⛔ a take and a cancel of one slot share a book entry"
        );
    }
}

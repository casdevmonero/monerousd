// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ SAFE AT SCALE — `Class::VaultMerge`: A CUSTODY VAULT AT HALF STRENGTH OR UNDER HANDS ITS LEDGERS TO ANOTHER VAULT
//! (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3d).
//!
//! Each custody vault keeps its own ledgers (`peg::vault_ledger`). A vault's holdings do not shrink when its members
//! leave: a vault of sixteen that thinned to one would leave one custodian alone with coins far past its own bond.
//! So a vault of eight members or fewer may MERGE: its ledgers' totals are added into another vault's, its own
//! ledgers return to their genesis pairs, and a custodian may then leave it (the unbond door refuses a leave that
//! would thin a vault under eight while its ledgers stand moved and another vault can take them).
//!
//! The object: the two vaults; the receiving ledgers' pairs after; two sum proofs per ledger kind (the decider's
//! transition carrier under the `VaultMerge` domain, each against the chain's OWN two pairs — so nothing is created
//! and nothing is lost); the receiving vault's bound proof (`peg::VaultRide`, the deposit door's own) or none; and two
//! lists of signatures, each over the statement its signers' own nodes derive:
//!   • the RELEASE (`PegLedger::vault_merge_release_msg`: both vaults' pairs as the chain holds them) — two thirds of
//!     the retiring vault, and with no bound proof two thirds of the whole bonded weight as well;
//!   • the ACCEPTANCE (`PegLedger::vault_merge_msg`: the same pre-state and the pairs after) — two thirds of the
//!     receiving vault, whose custodians derived those pairs from their own openings of both vaults' ledgers.
//! Everything that decides a merge lives in `PegLedger::check_vault_merge` / `vault_merge` (its §9.6 answers are
//! there); this module is the one encoding and the one seam from a block's bytes to that door.
//!
//! BORROWED: THORChain's vault migration at churn (a retiring Asgard vault's funds and accounting move to the active
//! vaults before its members leave); the registration object's shape for an attested object with no note
//! (`wrapped_asset_tx`).
//! SCALE: with its bound proof, two vaults whatever the bonded set — at most thirty-two signatures, two sum proofs
//! per ledger kind the retiring vault moved (the kinds are the protocol's list `peg::CUSTODY_LEDGER_KINDS`, four
//! today) and the ride's two. Without it (the receiving vault would stand past its authority, or a coin ledger moves —
//! coin ledgers have no ride yet) the whole bonded set's two thirds sign the release too, as for a deposit past a
//! vault's authority: that list is bounded by the chain's attestor ceiling (`MAX_RELEASE_ATTESTORS`).
//! cons: a merge of all four ledger kinds carries eight proofs (about 165 KB each as measured on the ride's) plus the
//! ride (329,628 B measured); a ledger that never moved carries none. The whole-set path is not fixed-size.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The most signatures the RELEASE list carries: the chain's one attestor ceiling (the deposit object's own), reached
/// only on the whole-set path; under a bound proof it holds at most one vault's members.
pub const MAX_RELEASE_ATTESTORS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;
/// The most signatures the ACCEPTANCE list carries: one vault's members.
pub const MAX_ACCEPT_ATTESTORS: usize = crate::custody_vaults::VAULT_MAX;
/// The two vaults a merge names: the retiring one and the receiving one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMergeHeader {
    pub from: u32,
    pub into: u32,
}

/// The EXACT payload type this class's bytes deserialize to: the two vaults; one leg per ledger kind the retiring
/// vault moved (`peg::MergeLeg`: the kind, the receiving pair after, the two sum proofs), in ascending kind order; the
/// receiving vault's ride bytes (empty on the whole-set path); then the release and the acceptance attestations as raw
/// `(pubkey, sig)` pairs. The legs are a LIST over `peg::CUSTODY_LEDGER_KINDS`, so a coin added to the bridge is
/// carried by this encoding as it stands.
pub type VaultMergePayload = (VaultMergeHeader, Vec<crate::peg::MergeLeg>, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>);

/// A merge as its parts: what the door reads. A custodian's prove answers one with both signature lists empty
/// (`Node::vault_merge_prove`); the lists are filled by the two vaults' signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMerge {
    pub header: VaultMergeHeader,
    /// O1-FOOTPRINT-REVIEWED: at most one per entry of `peg::CUSTODY_LEDGER_KINDS` (`decode`), each proof under the decider's bound.
    pub legs: Vec<crate::peg::MergeLeg>,
    pub ride: Vec<u8>,
    pub release: Vec<MintAttestor>,
    pub accept: Vec<MintAttestor>,
}

fn pairs_of(attestors: &[MintAttestor]) -> Vec<(Vec<u8>, Vec<u8>)> {
    attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect()
}

impl VaultMerge {
    /// The canonical payload bytes (unframed). An encode failure yields EMPTY bytes, which no reader decodes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(&(self.header, self.legs.clone(), self.ride.clone(), pairs_of(&self.release), pairs_of(&self.accept))).unwrap_or_default()
    }

    /// The ONE wire encoding: the canonical payload framed under its own class.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        frame(Class::VaultMerge, &self.encode())
    }

    /// Wrap this object as the transaction that carries it into a block — the publisher shape the registration uses
    /// (`wrapped_asset_tx::as_pq_tx`). A merge mints nothing and burns nothing, so every note, nullifier and witness
    /// list is empty, which is what `chain_object::wrapper_binds_object` requires for a class that names no note. The
    /// anti-spam stamp is ground as a real submit grinds it: 2^stamp_bits expected tries.
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

fn attestors_in_bounds(pairs: &[(Vec<u8>, Vec<u8>)], most: usize) -> bool {
    !pairs.is_empty()
        && pairs.len() <= most
        && pairs.iter().all(|(pk, sig)| !pk.is_empty() && !sig.is_empty() && pk.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX)
}

/// THE ONE DECODE, and the one place this class's bounds live: strict full consumption; two distinct vaults; legs in
/// their one order (`PegLedger::merge_legs_in_order`: at least one, each a custody-funded ledger kind, strictly
/// ascending, so at most one per kind — a merge that moves no ledger is not an object), each leg with both its proofs
/// and none past the decider's proof bound; ride bytes that are empty or a bound proof (`VaultRide::decode`, itself
/// bounded); a release list of one to `MAX_RELEASE_ATTESTORS` and an acceptance list of one to
/// `MAX_ACCEPT_ATTESTORS`, inside the ML-DSA ceilings.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<VaultMerge> {
    let (header, legs, ride, release, accept) = decode_exact::<VaultMergePayload>(payload)?;
    if header.from == header.into || header.from > crate::peg::VAULT_INDEX_MAX || header.into > crate::peg::VAULT_INDEX_MAX {
        return None;
    }
    if !crate::peg::PegLedger::merge_legs_in_order(&legs) || !attestors_in_bounds(&release, MAX_RELEASE_ATTESTORS) || !attestors_in_bounds(&accept, MAX_ACCEPT_ATTESTORS) {
        return None;
    }
    let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
    if legs.iter().any(|l| l.reserve_sum.is_empty() || l.minted_sum.is_empty() || l.reserve_sum.len() > max || l.minted_sum.len() > max) {
        return None;
    }
    if !ride.is_empty() && !crate::peg::VaultRide::decode(&ride).is_some_and(|r| r.by_vault()) {
        return None; // one encoding: a bound proof, or no ride bytes at all
    }
    let list = |pairs: Vec<(Vec<u8>, Vec<u8>)>| pairs.into_iter().map(|(pubkey, sig)| MintAttestor { pubkey, sig }).collect();
    Some(VaultMerge { header, legs, ride, release: list(release), accept: list(accept) })
}

/// ⭐ SAFE AT SCALE, stage three (spec §3f R7, R8) — ONE CUSTODIAN'S SIGNATURE OVER A STATEMENT OF THE MERGE ITS CHAIN
/// SAYS IS DUE (`WireMsg::VaultMergeSig`), in the key lane's shape. `posts` is `None` for the RELEASE (the retiring
/// vault's statement: both vaults' pairs as the chain holds them — every word a chain fact) and `Some` for the
/// ACCEPTANCE (the receiving vault's: the same pre-state and the pairs after, which each custodian of the receiving
/// vault derived from its own openings of both vaults' ledgers). The receiver forms the signed message from ITS OWN
/// chain (`PegLedger::vault_merge_release_msg` / `vault_merge_accept_msg`), so a signature over another pre-state
/// verifies under nothing; a custodian of the receiving vault that holds both openings and two thirds of each list
/// proves the sums and frames the object.
/// COINS FIRST (R7): a custodian signs the ACCEPTANCE only when its own sources already show the coins the merged
/// ledgers will count (`Node::own_vault_merge_sigs`) — the receiving vault never takes on a ledger whose coins it
/// cannot see, and that is the whole of what "coins first" needs: a release alone moves nothing.
/// §9.6 (a gossip door): (1) no PoW — a relay cache; (2) the signer's ML-DSA signature over the message the receiver
/// forms; (3) no value moves — the door at the fold decides, with its sum proofs; (4) a repeat is not new; (5) one
/// signature verify, a book bounded per signer and merge; (6) parity with `VaultKeySig`; (7) scale — two vaults'
/// signers (and the whole set's release only while the set is small enough to fit the object: `MAX_RELEASE_ATTESTORS`);
/// (8) a persuasive message gains nothing: a release is chain facts, an acceptance is each signer's own derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMergeSig {
    pub header: VaultMergeHeader,
    /// O1-FOOTPRINT-REVIEWED: at most one per entry of `peg::CUSTODY_LEDGER_KINDS` (`decode`).
    pub posts: Option<Vec<crate::peg::MergePost>>,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl VaultMergeSig {
    /// The one wire encoding (an encoding failure is an empty vector, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Strict full-consumption decode: two distinct vaults inside the index bound; an acceptance's pairs in the one
    /// order a merge carries its legs (each a custody-funded kind, strictly ascending, at least one); the ML-DSA ceilings.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: VaultMergeSig = decode_exact(bytes)?;
        let h = s.header;
        if h.from == h.into || h.from > crate::peg::VAULT_INDEX_MAX || h.into > crate::peg::VAULT_INDEX_MAX {
            return None;
        }
        if let Some(posts) = &s.posts {
            let kinds = crate::peg::CUSTODY_LEDGER_KINDS;
            if posts.is_empty() || posts.len() > kinds.len() || posts.iter().any(|(a, _)| !kinds.contains(a)) || !posts.windows(2).all(|w| w[0].0 < w[1].0) {
                return None;
            }
        }
        (!s.pubkey.is_empty() && !s.sig.is_empty() && s.pubkey.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && s.sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX).then_some(s)
    }

    /// A statement's identity in the signature book: the two vaults, which statement it is, and an acceptance's pairs.
    #[must_use]
    pub fn statement_digest(header: &VaultMergeHeader, posts: Option<&[crate::peg::MergePost]>) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("musdm.vault-merge.statement.v1");
        h.update(&postcard::to_stdvec(&(header, posts)).unwrap_or_default());
        *h.finalize().as_bytes()
    }
}

/// What applying a block-carried merge did on this node.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeApply {
    /// The blob is not a merge (another class, or out of bounds): nothing was touched.
    NotMerge,
    /// The door applied it: the receiving ledgers stand on the posts, the retiring ones at genesis.
    Merged,
    /// The door refused it: nothing was touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> crate::spend_frontier::Digest4 {
        crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(b)).unwrap()
    }

    fn leg(asset: u32) -> crate::peg::MergeLeg {
        crate::peg::MergeLeg { asset, post: (d(1), d(2)), reserve_sum: vec![3u8; 8], minted_sum: vec![4u8; 8] }
    }

    fn smallest() -> VaultMerge {
        let one = vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
        VaultMerge { header: VaultMergeHeader { from: 1, into: 0 }, legs: vec![leg(crate::peg::NATIVE_PEG_ASSET_ID)], ride: Vec::new(), release: one.clone(), accept: one }
    }

    /// The codec alone: one encoding round-trips, and every out-of-bounds shape is refused at the decode (the door
    /// behind it is pinned across two nodes in `node::pins`).
    // TWO-PARTY-REVIEWED: a codec bound has one endpoint by nature; the second endpoint of this class — a peer fed only
    // the block — is `node::vault_pins::safe_at_scale_a_thinned_vault_merges_its_ledgers_into_another_on_both_nodes_and_every_forgery_is_refused`.
    #[test]
    fn a_merge_has_one_encoding_and_every_out_of_bounds_shape_is_refused_at_the_decode() {
        let m = smallest();
        let wire_bytes = m.wire();
        let (class, payload) = unframe(&wire_bytes).expect("framed");
        assert_eq!(class, Class::VaultMerge, "it frames under its own class");
        let back = decode(payload).expect("the smallest merge decodes");
        assert_eq!(back, m);
        assert_eq!(back.encode(), payload, "one encoding: decode then encode is the same bytes");

        let refused = |m: &VaultMerge| decode(&m.encode()).is_none();
        let mut tail = payload.to_vec();
        tail.push(0);
        assert!(decode(&tail).is_none(), "⛔ a trailing byte was read as a merge");
        assert!(refused(&VaultMerge { header: VaultMergeHeader { into: 1, ..m.header }, ..m.clone() }), "⛔ a vault merged into itself");
        // the legs: every custody-funded kind once, ascending, is the widest merge — and it decodes
        let kinds = crate::peg::CUSTODY_LEDGER_KINDS;
        let widest = VaultMerge { legs: kinds.iter().map(|a| leg(*a)).collect(), ..m.clone() };
        assert_eq!(decode(&widest.encode()), Some(widest.clone()), "a merge of every ledger kind the chain lists decodes");
        let mut past = widest.clone();
        past.legs.push(leg(kinds[kinds.len() - 1] + 1));
        assert!(refused(&past), "⛔ a leg for a kind outside the list decoded");
        assert!(refused(&VaultMerge { legs: vec![leg(kinds[0]), leg(kinds[0])], ..m.clone() }), "⛔ one ledger kind twice decoded");
        assert!(refused(&VaultMerge { legs: vec![leg(kinds[1]), leg(kinds[0])], ..m.clone() }), "⛔ a second order of the same legs decoded");
        let mut missing = m.clone();
        missing.legs[0].minted_sum.clear();
        assert!(refused(&missing), "⛔ a leg with one of its two proofs missing decoded");
        let mut wide = m.clone();
        wide.legs[0].reserve_sum = vec![0u8; crate::solvency::SolvencyProof::MAX_PROOF_BYTES + 1];
        assert!(refused(&wide), "⛔ a proof past the decider's bound decoded");
        assert!(refused(&VaultMerge { legs: Vec::new(), ..m.clone() }), "⛔ a merge that moves nothing decoded");
        assert!(refused(&VaultMerge { release: Vec::new(), ..m.clone() }), "⛔ a merge the retiring vault never released decoded");
        assert!(refused(&VaultMerge { accept: Vec::new(), ..m.clone() }), "⛔ a merge the receiving vault never accepted decoded");
        assert!(refused(&VaultMerge { release: vec![m.release[0].clone(); MAX_RELEASE_ATTESTORS + 1], ..m.clone() }), "⛔ more release signatures than the chain's ceiling decoded");
        assert!(refused(&VaultMerge { accept: vec![m.accept[0].clone(); MAX_ACCEPT_ATTESTORS + 1], ..m.clone() }), "⛔ more acceptance signatures than one vault holds decoded");
        // ride bytes: empty, or a bound proof — never a bare vault name, never junk
        assert!(refused(&VaultMerge { ride: crate::peg::VaultRide::of(3).encode(), ..m.clone() }), "⛔ a ride with no proofs decoded");
        assert!(refused(&VaultMerge { ride: vec![7u8; 5], ..m.clone() }), "⛔ junk ride bytes decoded");
        let ride = crate::peg::VaultRide { vault: 0, sum_commit: d(5), sum: vec![1u8; 8], bound: vec![2u8; 8] };
        assert!(!refused(&VaultMerge { ride: ride.encode(), ..m }), "a merge under its bound proof decodes");
    }
}

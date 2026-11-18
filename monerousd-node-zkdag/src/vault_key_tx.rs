// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ SAFE AT SCALE, stage three — `Class::VaultKey`: A CUSTODY VAULT TAKES THE KEY OF ITS MEMBERS, AND RETIRES A KEY IT
//! REPLACED (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3f R1, R2, R4).
//!
//! A Bitcoin reserve coin is locked to the member set that was live when it was deposited, and a Monero wallet belongs
//! to one member set. So which custodians' keys hold a vault's coins is state the chain must hold: it is what a
//! deposit address has one source in, and what decides when a custodian that left may have its collateral back — only
//! once no key that is still alive names it ("no key outlives its bond", R4; proven first in the lifecycle model,
//! `models/custody-lifecycle/src/keys.rs`, invariant K1).
//!
//! Two kinds, one class:
//!   • TAKE — the vault's members, as the chain seats them, state the key of exactly that member set and the Monero
//!     main address their own wallets report for it. From the block that carries it the new key is the vault's deposit
//!     address; the key it replaces stays alive for its address window (R2: make before break).
//!   • RETIRE — the vault's current members state that a replaced key is finished: its window has passed (the chain
//!     checks that) and no coin is left under it (each signer checks its own source). The key leaves the record, and a
//!     leaver it named is no longer held by it.
//! Everything that decides either lives in `PegLedger::check_vault_key_take` / `check_vault_key_retire` (their §9.6
//! answers are there); this module is the one encoding and the one seam from a block's bytes to those doors.
//!
//! BORROWED: THORChain — a new vault's key is adopted by the chain only on its members' own keygen result, and a
//! retiring vault keeps its status until its funds have migrated; the registration object's shape for an attested
//! object with no note (`wrapped_asset_tx`).
//! SCALE: one vault's signatures and one member list (sixteen at most on a chain of vaults) and one address — whatever
//! the bonded set, the deposits in flight or the height.
//! cons: one small object per re-key and one per retirement (sixteen ML-DSA signatures and keys: about 84 KB at
//! sixteen signers, the size of any vault-signed statement); a leaver waits for its old vault's retire (spec §3f R4b
//! is what makes that wait cost the vault, not the leaver — not built in this step).

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The most signatures a key statement carries, and the most members a key names: the chain's one attestor ceiling
/// (one vault's sixteen on a chain of vaults; a one-vault chain's whole custody set).
pub const MAX_KEY_ATTESTORS: usize = crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS;

/// What a key statement names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultKeyHeader {
    /// The vault, its member set (sorted — the chain's own seating) and the Monero main address of that set.
    Take {
        vault: u32,
        /// O1-FOOTPRINT-REVIEWED: bounded by `MAX_KEY_ATTESTORS` in `decode`.
        members: Vec<[u8; 32]>,
        /// O1-FOOTPRINT-REVIEWED: bounded by `peg::VAULT_KEY_ADDRESS_MAX` in `decode`.
        xmr_address: Vec<u8>,
    },
    /// The vault and the replaced key, named by the chain tick it became the key at (`VaultKeyRow::since_tick`).
    Retire { vault: u32, since_tick: u64 },
}

impl VaultKeyHeader {
    #[must_use]
    pub fn vault(&self) -> u32 {
        match self {
            VaultKeyHeader::Take { vault, .. } | VaultKeyHeader::Retire { vault, .. } => *vault,
        }
    }
}

/// The EXACT payload type this class's bytes deserialize to: the header and the attestations as raw `(pubkey, sig)`.
pub type VaultKeyPayload = (VaultKeyHeader, Vec<(Vec<u8>, Vec<u8>)>);

/// A key statement as its parts: what the door reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKey {
    pub header: VaultKeyHeader,
    pub attestors: Vec<MintAttestor>,
}

impl VaultKey {
    /// The canonical payload bytes (unframed). An encode failure yields EMPTY bytes, which no reader decodes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let att: Vec<(Vec<u8>, Vec<u8>)> = self.attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect();
        postcard::to_stdvec(&(self.header.clone(), att)).unwrap_or_default()
    }

    /// The ONE wire encoding: the canonical payload framed under its own class.
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        frame(Class::VaultKey, &self.encode())
    }

    /// Wrap this object as the transaction that carries it into a block — the registration's publisher shape
    /// (`wrapped_asset_tx::as_pq_tx`): no note, no nullifier, no lane (the statement binds the key record's pre-state,
    /// which its own apply changes — a replay names a record the chain no longer holds). The anti-spam stamp is ground
    /// as a real submit grinds it.
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

/// A header's own bounds — the ONE definition the object's decode and the signature lane's decode both read: a vault
/// index inside the chain's range; a TAKE's members one to `MAX_KEY_ATTESTORS`, strictly ascending (sorted, no id
/// twice), its address inside `peg::VAULT_KEY_ADDRESS_MAX`.
#[must_use]
pub fn header_in_bounds(header: &VaultKeyHeader) -> bool {
    if header.vault() > crate::peg::VAULT_INDEX_MAX {
        return false;
    }
    match header {
        VaultKeyHeader::Take { members, xmr_address, .. } => {
            !members.is_empty() && members.len() <= MAX_KEY_ATTESTORS && members.windows(2).all(|w| w[0] < w[1]) && xmr_address.len() <= crate::peg::VAULT_KEY_ADDRESS_MAX
        }
        VaultKeyHeader::Retire { .. } => true,
    }
}

/// ⭐ SAFE AT SCALE, stage three — ONE CUSTODIAN'S SIGNATURE OVER A KEY STATEMENT: the unit of the key lane
/// (`WireMsg::VaultKeySig`). Every custodian of a vault derives the SAME header from its own chain — the vault's seats
/// and, for a take, the Monero address its own wallet reports for that set (`Node::vault_key_take_due`), or the
/// replaced key its own sources show empty (`Node::vault_key_retires_due`) — signs it ON ITS OWN and gossips this; a
/// node gathers them against ITS OWN chain (`Node::vault_key_sig_ingest`: the message is formed here, never read from
/// the wire), and whoever holds two thirds of that vault frames the object. No operator, no route: the trigger is
/// the chain's own seats and record.
/// BORROWED: this tree's liquidation attestation lane (`liquidation_tx::LiquidationSig`); THORChain's keygen result,
/// posted by each member of the new vault and adopted at two thirds.
/// SAFE AT SCALE: one message per custodian per statement — a vault's sixteen at most; a node keeps at most one
/// header per signer per vault and kind (`Node::vault_key_sig_ingest`), whatever the bonded set or the height.
/// AI RESISTANT: a signer signs only the statement its own node derived; a gatherer counts a signature only over the
/// message its own chain forms. A relayed header that names other members, or another pre-state, verifies under
/// nothing here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeySig {
    pub header: VaultKeyHeader,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl VaultKeySig {
    /// The one wire encoding (an encoding failure is an empty vector, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Strict full-consumption decode; the header's bounds and the ML-DSA ceilings live here.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: VaultKeySig = decode_exact(bytes)?;
        (header_in_bounds(&s.header) && !s.pubkey.is_empty() && !s.sig.is_empty() && s.pubkey.len() <= crate::peg_attest::PEG_ATTEST_PUBKEY_MAX && s.sig.len() <= crate::peg_attest::PEG_ATTEST_SIG_MAX).then_some(s)
    }

    /// A header's identity in the signature book: blake3 over its one encoding.
    #[must_use]
    pub fn header_digest(h: &VaultKeyHeader) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("musdm.vault-key.header.v1");
        hasher.update(&postcard::to_stdvec(h).unwrap_or_default());
        *hasher.finalize().as_bytes()
    }
}

/// THE ONE DECODE, and the one place this class's bounds live: strict full consumption; the header's own bounds
/// ([`header_in_bounds`]); one to `MAX_KEY_ATTESTORS` attestations inside the ML-DSA ceilings.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<VaultKey> {
    let (header, pairs) = decode_exact::<VaultKeyPayload>(payload)?;
    if !header_in_bounds(&header) {
        return None;
    }
    if pairs.is_empty()
        || pairs.len() > MAX_KEY_ATTESTORS
        || pairs.iter().any(|(pk, sig)| pk.is_empty() || sig.is_empty() || pk.len() > crate::peg_attest::PEG_ATTEST_PUBKEY_MAX || sig.len() > crate::peg_attest::PEG_ATTEST_SIG_MAX)
    {
        return None;
    }
    let attestors = pairs.into_iter().map(|(pubkey, sig)| MintAttestor { pubkey, sig }).collect();
    Some(VaultKey { header, attestors })
}

/// What applying a block-carried key statement did on this node.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyApply {
    /// The blob is not a key statement (another class, or out of bounds): nothing was touched.
    NotKey,
    /// The door applied a take: the vault's deposit address is the new key; the one it replaced is alive, replaced.
    Taken,
    /// The door applied a retire: the replaced key left the record.
    Retired,
    /// The door refused it: nothing was touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(test)]
mod tests {
    use super::*;

    fn smallest() -> VaultKey {
        VaultKey { header: VaultKeyHeader::Take { vault: 0, members: vec![[7u8; 32]], xmr_address: Vec::new() }, attestors: vec![MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }] }
    }

    /// The codec alone: one encoding round-trips, and every out-of-bounds shape is refused at the decode (the doors
    /// behind it are pinned across two parties in `peg::tests` and across nodes in `node::vault_pins`).
    // TWO-PARTY-REVIEWED: a codec bound has one endpoint by nature; the second endpoint of this class — a peer fed only
    // the block — is `node::vault_pins::safe_at_scale_a_leavers_collateral_returns_only_when_no_alive_key_names_it_on_every_node`.
    #[test]
    fn a_key_statement_has_one_encoding_and_every_out_of_bounds_shape_is_refused_at_the_decode() {
        let m = smallest();
        let wire_bytes = m.wire();
        let (class, payload) = unframe(&wire_bytes).expect("framed");
        assert_eq!(class, Class::VaultKey, "it frames under its own class");
        let back = decode(payload).expect("the smallest take decodes");
        assert_eq!(back, m);
        assert_eq!(back.encode(), payload, "one encoding: decode then encode is the same bytes");
        let retire = VaultKey { header: VaultKeyHeader::Retire { vault: 3, since_tick: 77 }, ..m.clone() };
        assert_eq!(decode(&retire.encode()), Some(retire.clone()), "a retire decodes");

        let refused = |k: &VaultKey| decode(&k.encode()).is_none();
        let take = |members: Vec<[u8; 32]>, xmr_address: Vec<u8>| VaultKey { header: VaultKeyHeader::Take { vault: 0, members, xmr_address }, ..m.clone() };
        let mut tail = payload.to_vec();
        tail.push(0);
        assert!(decode(&tail).is_none(), "⛔ a trailing byte was read as a key statement");
        assert!(refused(&take(Vec::new(), Vec::new())), "⛔ a key of nobody decoded");
        assert!(refused(&take(vec![[2u8; 32], [1u8; 32]], Vec::new())), "⛔ a second order of the same members decoded");
        assert!(refused(&take(vec![[1u8; 32], [1u8; 32]], Vec::new())), "⛔ one custodian named twice decoded");
        let wide: Vec<[u8; 32]> = (0..=MAX_KEY_ATTESTORS as u32).map(|i| { let mut id = [0u8; 32]; id[..4].copy_from_slice(&i.to_be_bytes()); id }).collect();
        assert!(refused(&take(wide.clone(), Vec::new())), "⛔ more members than the chain's ceiling decoded");
        assert!(!refused(&take(wide[..MAX_KEY_ATTESTORS].to_vec(), Vec::new())), "a key of exactly the ceiling decodes");
        assert!(refused(&take(vec![[1u8; 32]], vec![b'4'; crate::peg::VAULT_KEY_ADDRESS_MAX + 1])), "⛔ an address past the record's bound decoded");
        assert!(!refused(&take(vec![[1u8; 32]], vec![b'4'; crate::peg::VAULT_KEY_ADDRESS_MAX])), "an address at the bound decodes");
        assert!(refused(&VaultKey { header: VaultKeyHeader::Retire { vault: crate::peg::VAULT_INDEX_MAX + 1, since_tick: 0 }, ..m.clone() }), "⛔ a vault index outside the chain's range decoded");
        assert!(refused(&VaultKey { attestors: Vec::new(), ..m.clone() }), "⛔ a statement nobody signed decoded");
        assert!(refused(&VaultKey { attestors: vec![m.attestors[0].clone(); MAX_KEY_ATTESTORS + 1], ..m.clone() }), "⛔ more signatures than the chain's ceiling decoded");
        assert!(refused(&VaultKey { attestors: vec![MintAttestor { pubkey: Vec::new(), sig: vec![2u8; 4] }], ..m }), "⛔ an attestation with no key decoded");
    }
}

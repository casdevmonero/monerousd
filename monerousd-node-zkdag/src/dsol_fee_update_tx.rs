// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-12 L3 — THE TIGHTEN-ONLY PUBLISHER-FEE UPDATE, `Class::DsolFeeUpdate` (byte 37; bridge spec §10 contract rule 2:
//! "after deploy the publisher may only LOWER the rate — a raise would surprise existing users (ADOPTABLE); a contract is never
//! paused or held by its fee").
//!
//! The deployer (the key whose `pubkey_id` the contract's manifest binds) signs a new, LOWER fee for its contract. The object
//! carries the contract's current manifest and storage root with the compact path into the ONE contract-state root; the fold
//! verifies the leaf, the signature, the direction (strictly lower), and moves the leaf to the same storage under the new
//! manifest. Every call built on the old manifest is then refused by its own stale path (the leaf moved) and re-proven on the
//! new words — a caller can never be charged more than the manifest it read, and after a cut it pays less. No fee spend rides
//! the update (it moves no value); its replay guard is a one-time id over `(cid, new fee)` on the lane.
//!
//! §9.6: (1) PoW — the carrying block's and the tx stamp; (2) the deployer's ML-DSA-65 signature against the manifest's
//! `deployer_id`, and the leaf against the root; (3) value — none moves; (4) replay — `one_time_id_nf(ONE_TIME_DSOL_FEE_UPDATE,
//! blake3(cid ‖ new fee))`, refused by the spent set (and a second identical update finds the leaf already moved); (5) bounded —
//! one signature, one path; (6) parity with the deploy door: the same leaf check, the same signature shape, no burn (the deploy
//! paid for the contract once).
//!
//! ROOT-LAYER: the fee a call must pay is read from the leaf the fold writes here; nothing else writes a manifest after deploy.
//! MEASURED: the pins below — a cut applies on two nodes and a call on the old manifest is refused while one on the new pays
//! less; a raise, an equal fee, a non-deployer's signature, a body changed after signing and a replay are each refused.
//! MUST-STAY-GREEN: every deploy and call pin (the leaf's shape is unchanged; only its manifest word moves).
//! BORROWED: a contract's owner-only parameter change signed by the owner (an `onlyOwner` setter), with the chain refusing the
//! direction the users were not promised (a tighten-only governance bound, as the chain's own upgrade lane §BR-10 is).

use crate::contract_state::{update_root, PathWire};
use crate::dsol_deploy_tx::{ContractManifest, DSOL_PUBLISHER_FEE_MAX_ATOMIC, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES};
use crate::spend_frontier::Digest4;

/// The one-time id kind of a fee update on the nullifier lane.
pub const ONE_TIME_DSOL_FEE_UPDATE: u8 = 9;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsolFeeUpdateTx {
    pub cid: [u8; 32],
    /// The contract's CURRENT manifest (the leaf's), proven by the path.
    pub manifest: ContractManifest,
    /// The contract's current storage root (canonical digest bytes), as the leaf holds it.
    pub storage_root: [u8; 32],
    pub state_path: PathWire,
    /// The new fee, 8 little-endian bytes — strictly below the manifest's.
    pub new_fee_le: [u8; 8],
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_PK_BYTES`] — the deployer's key (`pubkey_id` = the manifest's `deployer_id`).
    pub deployer_pk: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_SIG_BYTES`] — ML-DSA-65 over [`Self::signing_body`].
    pub sig: Vec<u8>,
}

/// The update's one-time key: `blake3("USDMD-DSOL-FEE-UPDATE-v1" ‖ cid ‖ new fee)`.
#[must_use]
pub fn fee_update_key(cid: &[u8; 32], new_fee_le: &[u8; 8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-DSOL-FEE-UPDATE-v1");
    h.update(cid);
    h.update(new_fee_le);
    *h.finalize().as_bytes()
}

impl DsolFeeUpdateTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DsolFeeUpdate, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<DsolFeeUpdateTx> {
        let t: DsolFeeUpdateTx = crate::chain_object::decode_exact(bytes)?;
        if t.deployer_pk.len() != ML_DSA_65_PK_BYTES || t.sig.len() != ML_DSA_65_SIG_BYTES {
            return None;
        }
        if t.state_path.sibs.len() > crate::contract_state::DEPTH || t.state_path.expand().is_none() {
            return None;
        }
        if crate::spend_frontier::cm_bytes_to_root(&t.storage_root).is_none() {
            return None;
        }
        if t.new_fee() > DSOL_PUBLISHER_FEE_MAX_ATOMIC {
            return None;
        }
        Some(t)
    }

    #[must_use]
    pub fn new_fee(&self) -> u64 {
        u64::from_le_bytes(self.new_fee_le)
    }

    /// The bytes the deployer signs: the object with the signature emptied (it carries no note, so nothing is rewritten).
    #[must_use]
    pub fn signing_body(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig = Vec::new();
        let mut pre = Vec::with_capacity(32 + unsigned.encode().len());
        pre.extend_from_slice(b"USDMD-DSOL-FEE-UPDATE-SIG-v1");
        pre.extend_from_slice(&unsigned.encode());
        pre
    }

    /// Signed by the key the manifest names as the deployer.
    #[must_use]
    pub fn authorised(&self) -> bool {
        crate::pqauth::pubkey_id(&self.deployer_pk) == self.manifest.deployer_id && crate::pqauth::ml_dsa_verify(&self.signing_body(), &self.deployer_pk, &self.sig)
    }

    /// Strictly lower than the manifest's fee (§10 rule 2; an equal fee changes nothing and is refused).
    #[must_use]
    pub fn tightens(&self) -> bool {
        self.new_fee() < self.manifest.fee()
    }

    /// The stateless half every door takes.
    #[must_use]
    pub fn self_authorised(&self) -> Option<&'static str> {
        if !self.authorised() {
            return Some("the update is not signed by the contract's deployer");
        }
        if !self.tightens() {
            return Some("a publisher fee may only be LOWERED after deploy (ADOPTABLE: a raise would surprise existing users)");
        }
        None
    }

    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        vec![crate::peg::one_time_id_nf(ONE_TIME_DSOL_FEE_UPDATE, &fee_update_key(&self.cid, &self.new_fee_le))]
    }

    /// The new manifest.
    #[must_use]
    pub fn new_manifest(&self) -> ContractManifest {
        self.manifest.with_fee(self.new_fee())
    }

    /// The contract-state root after the cut, or `None` when the carried leaf is not the chain's.
    #[must_use]
    pub fn root_after(&self, root: Digest4) -> Option<Digest4> {
        let sibs = self.state_path.expand()?;
        let storage = crate::spend_frontier::cm_bytes_to_root(&self.storage_root)?;
        update_root(root, &self.cid, self.manifest.leaf(storage), self.new_manifest().leaf(storage), &sibs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeUpdateApply {
    NotUpdate,
    Applied(Digest4),
    Refused(&'static str),
}

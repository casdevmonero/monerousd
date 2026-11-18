// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ §BR-12 / DSOL door landing 1 — THE DEPLOY DOOR, `Class::DsolDeploy` (byte 19; docs/DSOL-NODE-DOOR-SPEC.md §9 D6, §12).
//!
//! A contract is DEPLOYED by a chain object the block carries and every node applies at the carrying block's FOLD, in
//! canonical order (DB-274's lesson; the asset creation's shape): the deployer pays the base creation price as a USDm BURN
//! inside the object (`CreationFee`, the same carrier an asset creation uses — a public `out0` destroys exactly the price
//! into a commitment no key opens, the welded network fee rides on top, `out1` is the change), and the fold inserts the
//! contract's leaf `P(leaf(code_id), empty storage root)` into the ONE contract-state root ([`crate::contract_state`]) from
//! the non-membership path the object carries. The node stores NO code and NO per-contract map: the code rides this object
//! into the block's record (DA for provers), the root is one word in the ledger.
//!
//! THE PUBLISHER-FEE MANIFEST (§BR-12, bridge spec §10): `publisher_fee_atomic` — a FLAT USDm amount every call of this
//! contract pays to the deployer's per-entity key (`publisher_spk`, sealed under `publisher_ek`), enforced by the CALL door
//! (landing 2) on every node from this deploy's words, so any front end pays the same fee. Stated deviation from the user's
//! "rate in basis points": a call carries no public value a rate could apply to (a contract is a predicate plus an effect
//! emitter, never a vault — spec §4.3), so the one enforceable form is a per-call amount; the wallet shows it in dollars first.
//!
//! §9.6, answered: (1) PoW — the carrying block's, and the tx stamp like every tx; (2) proof — the deployer's ML-DSA-65
//! signature over the body, and the fee burn's bond-validity carrier (`admissible`); the fold adds the fee note's membership
//! and the state path against the CURRENT root; (3) value — the burn destroys the price (credited to the four fee pools at the
//! fold like a creation's), nothing is minted, the change is the carrier's own `out1`; (4) replay — the object's own
//! nullifiers are `one_time_id_nf(ONE_TIME_DSOL_DEPLOY, cid)` and the fee note's, refused by the spent set on every node;
//! (5) bounded — one carrier, one member step, one compact path (≤ 256 siblings), code ≤ [`DSOL_CODE_BYTES_MAX`]; (6) parity
//! with `AssetCreate`: every check it runs, plus the signature and the state insert. The token registry is NOT appended (one
//! tree binds `code_id` to `cid`; two trees would be two truths — a stated deviation from spec §1's registry path).
//!
//! ROOT-LAYER: the deploy is PRODUCED as one chain object here, decided at the fold on every node; the wallet only builds
//!   and the route only publishes. MEASURED: the pins below — two nodes reach one contract-state root and one fee-pool total
//!   from the block alone; a short or lifted burn, a forged signature, a stale path and a duplicate cid are refused on both.
//! MUST-STAY-GREEN: every `AssetCreate` pin (its doors are untouched; the fee check it uses is now shared, not moved).
//!
//! BORROWED: a contract creation is a transaction that pays its fee from its own input (Bitcoin inputs − outputs; Ethereum's
//! CREATE pays gas), its address is a function of the creating transaction (Ethereum's `CREATE` address), and the account
//! trie holds `(code hash, storage root)` under it (Ethereum's state trie).
//! DIGITAL-CASH-PRIVACY-REVIEWED: the code, its id, the height class, the fee manifest and the deployer's key are public by the
//! door's spec (§5: which contract); the burn's amount is the public price; the change is an ordinary confidential note.

use crate::asset_tx::CreationFee;
use crate::contract_state::{contract_leaf, insert_root, PathWire};
use crate::spend_frontier::Digest4;

/// The code bytes one deploy may carry. D7: the ROM bounds INSTRUCTIONS (`verify_dsol_call` refuses a program past
/// `DSOL_ROM_ROWS_MAX`), so the byte cap comes from the object's budget — one sixty-fourth of the 16 MiB bulk frame a block
/// travels in, so sixty-four deploys still fit one frame beside everything else a block carries.
pub const DSOL_CODE_BYTES_MAX: usize = 16 * 1024 * 1024 / 64;
/// The display name's bound (a label, never consensus).
pub const DSOL_NAME_BYTES_MAX: usize = 64;
/// ML-DSA-65 public key and detached signature sizes (FIPS 204).
pub const ML_DSA_65_PK_BYTES: usize = usdm_decider::dsol_vm::DSOL_CALLER_PK_BYTES;
pub const ML_DSA_65_SIG_BYTES: usize = 3_309;
/// ML-KEM-768 encapsulation key size (FIPS 203).
pub const ML_KEM_768_EK_BYTES: usize = fips203::ml_kem_768::EK_LEN;
/// The smallest table class the verifier lays (32 rows).
pub const DSOL_HEIGHT_CLASS_MIN: u8 = 5;
/// The largest publisher fee a manifest may name: 1,000 USDm per call (above it no honest call exists; refused at decode).
pub const DSOL_PUBLISHER_FEE_MAX_ATOMIC: u64 = 1_000 * 100_000_000;

/// The one-time id kind of a deploy on the nullifier lane: `one_time_id_nf(ONE_TIME_DSOL_DEPLOY, cid)`.
pub const ONE_TIME_DSOL_DEPLOY: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsolDeployTx {
    /// O1-FOOTPRINT-REVIEWED: bounded by [`DSOL_CODE_BYTES_MAX`] — the contract's bytecode, the transaction itself,
    /// released with it; the node keeps none of it (the root binds `blake3(code)`).
    pub code: Vec<u8>,
    /// The ONE table class every call of this contract pads to (D6: a per-wallet class would fingerprint the caller).
    pub height_class: u8,
    /// A display label (≤ [`DSOL_NAME_BYTES_MAX`] bytes), never read by consensus.
    pub name: String,
    /// §BR-12 — the publisher fee every CALL pays, a flat USDm amount (0 = a free contract), as 8 little-endian bytes: a FIXED
    /// width, so the object's byte shape does not follow the fee's magnitude the way a varint would (L3's shape pin).
    pub publisher_fee_le: [u8; 8],
    /// The publisher's note spend key (`owner_spk`, canonical bytes): every call's fee note is owned by it — its opening is
    /// `owner_opening(spk, seed)` over a seed that is a PUBLIC function of the call (`dsol_call_tx::publisher_fee_seed`), so
    /// every node recomputes the note's commitment and the publisher's wallet derives the note from the chain with no
    /// sealing key at all (the fee amount is public by the manifest; the note's later spend is as unlinkable as any).
    pub publisher_spk: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_KEM_768_EK_BYTES`] — A4's contract view key (the storage blob's holders, D4).
    pub view_ek: Vec<u8>,
    /// D4 — `P(KC_DOMAIN ‖ k_c)`, the blob key's commitment every call's statement must match (landing 3 reads it).
    pub kc_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_PK_BYTES`] — the deployer's identity (the tighten-only fee update signs with it).
    pub deployer_pk: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_SIG_BYTES`] — ML-DSA-65 over [`Self::signing_body`].
    pub sig: Vec<u8>,
    /// The compact NON-membership path of `cid` against the contract-state root the deployer built it on.
    pub state_path: PathWire,
    /// The fee burn — the asset creation's shape, with `out0 = deploy_burn_cm(cid, price)`.
    pub fee: CreationFee,
}

/// The deploy price (§BR-14 item 4's burn shape): 10 USDm into the four pools. Its own constant since 2026-11-10, when a
/// token's and an NFT's creation prices were lowered and stopped being this number.
#[must_use]
pub fn dsol_deploy_fee_atomic() -> u64 {
    crate::params::DSOL_DEPLOY_FEE_ATOMIC
}

/// `cid = blake3("USDMD-DSOL-CID-v1" ‖ fee nullifier)` — unique because the nullifier SET refuses a second use of that note
/// (D6 #4), and known to the deployer before proving (the path and the burn are both built on it).
#[must_use]
pub fn dsol_cid(fee_nullifier: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-DSOL-CID-v1");
    h.update(fee_nullifier);
    *h.finalize().as_bytes()
}

/// The opening of a deploy's destroyed fee output: a public function of the cid, so every node recomputes
/// [`deploy_burn_cm`] and a burn is bound to exactly one deploy (the creation burn's shape).
#[must_use]
pub fn deploy_burn_opening(cid: &[u8; 32]) -> Digest4 {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"USDMD-DSOL-DEPLOY-FEE-BURN-v1");
    pre.extend_from_slice(cid);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// The commitment the deploy's fee burn MUST destroy.
#[must_use]
pub fn deploy_burn_cm(cid: &[u8; 32], price: u64) -> Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(price, usdm_decider::whir_rec_block::USDM_ASSET_TAG, deploy_burn_opening(cid))
}

/// The storage root a contract starts from: an empty trie (D6 #2 — a constructor proof moves it, landing 2).
#[must_use]
pub fn empty_storage_root() -> Digest4 {
    usdm_decider::dsol_vm::StorageTrie::default().root()
}

impl DsolDeployTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DsolDeploy, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode with every bound checked — a deploy outside them came from no honest wallet and is refused at decode,
    /// before any verify (§9.6 #5).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<DsolDeployTx> {
        let d: DsolDeployTx = crate::chain_object::decode_exact(bytes)?;
        if d.code.is_empty() || d.code.len() > DSOL_CODE_BYTES_MAX {
            return None;
        }
        if d.height_class < DSOL_HEIGHT_CLASS_MIN || d.height_class > usdm_decider::dsol_cpu_air::MAX_HEIGHT_LOG2 {
            return None;
        }
        if d.publisher_fee() > DSOL_PUBLISHER_FEE_MAX_ATOMIC {
            return None; // a fee no call could pay (§10 rule 2: a fee never holds a contract hostage; the bound is the decode's)
        }
        if d.name.len() > DSOL_NAME_BYTES_MAX {
            return None;
        }
        if d.view_ek.len() != ML_KEM_768_EK_BYTES {
            return None;
        }
        if d.deployer_pk.len() != ML_DSA_65_PK_BYTES || d.sig.len() != ML_DSA_65_SIG_BYTES {
            return None;
        }
        if d.state_path.sibs.len() > crate::contract_state::DEPTH || d.state_path.expand().is_none() {
            return None;
        }
        let f = &d.fee;
        if f.carrier.is_empty() || f.membership_carrier.is_empty() || f.membership_tip.is_empty() {
            return None;
        }
        if f.change_clue.is_empty() || f.change_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        if f.change_note.len() != crate::cover::PQ_NOTE_BYTES && f.change_note.len() != 64 {
            return None;
        }
        if crate::spend_frontier::note_cm_of(&f.change_note).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&f.nullifier).is_none()
            || crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit).is_none()
        {
            return None; // non-canonical digests came from no prover
        }
        Some(d)
    }

    /// `blake3(code)` — the contract's content address, the identity the state leaf binds to its storage.
    #[must_use]
    pub fn code_id(&self) -> [u8; 32] {
        *blake3::hash(&self.code).as_bytes()
    }

    /// The contract id, a function of the fee note this deploy spends ([`dsol_cid`]).
    #[must_use]
    pub fn cid(&self) -> [u8; 32] {
        dsol_cid(&self.fee.nullifier)
    }

    #[must_use]
    pub fn deploy_price(&self) -> u64 {
        dsol_deploy_fee_atomic()
    }

    /// The publisher fee as a number.
    #[must_use]
    pub fn publisher_fee(&self) -> u64 {
        u64::from_le_bytes(self.publisher_fee_le)
    }

    /// The deployer's identity (`pubkey_id(deployer_pk)`) — the one key that may later LOWER the fee (`dsol_fee_update_tx`).
    #[must_use]
    pub fn deployer_id(&self) -> [u8; 32] {
        crate::pqauth::pubkey_id(&self.deployer_pk)
    }

    /// The publisher-fee manifest this deploy binds into the contract's state leaf (what every call is measured against).
    #[must_use]
    pub fn manifest(&self) -> ContractManifest {
        ContractManifest {
            code_id: self.code_id(),
            publisher_fee_le: self.publisher_fee_le,
            publisher_spk: self.publisher_spk,
            deployer_id: self.deployer_id(),
            kc_commit: self.kc_commit,
            height_class: self.height_class,
        }
    }

    /// The leaf this deploy inserts: its code and manifest beside the empty storage root.
    #[must_use]
    pub fn leaf(&self) -> Digest4 {
        self.manifest().leaf(empty_storage_root())
    }

    /// The bytes the deployer signs: the whole object with the signature emptied (the signature cannot cover itself) and the
    /// fee's change note reduced to its 32-byte COMMITMENT. The carried object travels with that note rewritten to its
    /// 64-byte reference (`chain_object`'s `note_ref` arm, the block's note lane carries the body), so a signature over the
    /// full bytes would die at the first peer; the commitment is the one spelling both forms share, and it is what the
    /// carrier binds (`out1`), so nothing the signature should cover is lost. MEASURED (brb33/d1-pins.log): the honest deploy
    /// passed `admissible` on its own bytes and the pool door refused "the deployer's signature does not verify" on the
    /// carried form.
    #[must_use]
    pub fn signing_body(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig = Vec::new();
        if unsigned.fee.change_note.len() >= 32 {
            unsigned.fee.change_note.truncate(32);
        }
        let mut pre = Vec::with_capacity(32 + unsigned.encode().len());
        pre.extend_from_slice(b"USDMD-DSOL-DEPLOY-SIG-v1");
        pre.extend_from_slice(&unsigned.encode());
        pre
    }

    /// Does the deployer's key sign this object? (A1's shape for the deploy: the key that will update the fee is the key
    /// that deployed.)
    #[must_use]
    pub fn signature_verifies(&self) -> bool {
        crate::pqauth::ml_dsa_verify(&self.signing_body(), &self.deployer_pk, &self.sig)
    }

    /// Does the fee burn's carrier prove: the deployer spends one USDm note, `out0` destroys exactly the price into THIS
    /// deploy's burn commitment, `out1` is the change, and the network fee is welded on top? Stateless (the creation's
    /// `fee_carrier_verifies`, with the deploy's own burn commitment).
    #[must_use]
    pub fn fee_carrier_verifies(&self) -> bool {
        let f = &self.fee;
        let (Some(nf), Some(lc), Some(change)) = (
            crate::spend_frontier::cm_bytes_to_root(&f.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit),
            crate::spend_frontier::note_cm_of(&f.change_note),
        ) else {
            return false;
        };
        let price = self.deploy_price();
        usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
            &f.carrier,
            deploy_burn_cm(&self.cid(), price),
            change,
            nf,
            price,
            lc,
            usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        )
    }

    /// The pool door's whole stateless verdict: the signature and the fee carrier (the bounds were decode's).
    #[must_use]
    pub fn self_authorised(&self) -> bool {
        self.signature_verifies() && self.fee_carrier_verifies()
    }

    /// The object's own lane tags: the deploy's one-time id and the fee note's nullifier (§9.6 #4).
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        vec![crate::peg::one_time_id_nf(ONE_TIME_DSOL_DEPLOY, &self.cid()), self.fee.nullifier]
    }

    /// The new contract-state root this deploy produces from `root`, or `None` when its path does not open `root` with the
    /// empty leaf (the root moved since the deployer built the path, or the cid is occupied) or the path is malformed.
    #[must_use]
    pub fn root_after(&self, root: Digest4) -> Option<Digest4> {
        let sibs = self.state_path.expand()?;
        insert_root(root, &self.cid(), self.leaf(), &sibs)
    }
}

/// ⭐ THE CONTRACT MANIFEST a state leaf binds beside the storage root: the code identity and the publisher fee's terms. A
/// call carries it (the node holds only the root) and the path check proves it is the deployed one — so the fee a call pays
/// is measured against the deploy's words on every node, with no per-contract store (§BR-12, bridge spec §10 rule 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractManifest {
    pub code_id: [u8; 32],
    /// The publisher fee, 8 little-endian bytes (fixed width: the object's shape does not follow the fee's magnitude).
    pub publisher_fee_le: [u8; 8],
    pub publisher_spk: [u8; 32],
    /// `pubkey_id(deployer_pk)` — the one identity whose signature may LOWER the fee later (tighten-only, §10 rule 2).
    pub deployer_id: [u8; 32],
    /// D4 — the deploy's `P(KC_DOMAIN ‖ k_c)`: every call's storage blob must open it. In the LEAF, because the leaf is
    /// all a node keeps: a call's door reads the key commitment from the chain's own root, never from the call.
    pub kc_commit: [u8; 32],
    /// The ONE table class every call of this contract pads to (D6), in the leaf for the same reason: the door holds a
    /// call to its contract's class, and the blob's entry count follows from it.
    pub height_class: u8,
}

impl ContractManifest {
    #[must_use]
    pub fn fee(&self) -> u64 {
        u64::from_le_bytes(self.publisher_fee_le)
    }

    /// The same manifest at another fee (what a fee update writes).
    #[must_use]
    pub fn with_fee(self, fee: u64) -> Self {
        ContractManifest { publisher_fee_le: fee.to_le_bytes(), ..self }
    }

    /// `P(P(P(lanes(fee), leaf(publisher_spk)), leaf(deployer_id)), P(leaf(kc_commit), lanes(class)))` — the manifest's
    /// digest inside the leaf (D4: the key commitment and the class ride the leaf, FORMAT 2026-11-13).
    #[must_use]
    pub fn digest(&self) -> Digest4 {
        let fee_and_spk = crate::spend_frontier::poseidon_pair(
            usdm_decider::poseidon2_compress::lanes_of(&[0x4d41_4e49_4645_5354, self.fee()]),
            crate::spend_frontier::cm_bytes_to_leaf(&self.publisher_spk),
        );
        let base = crate::spend_frontier::poseidon_pair(fee_and_spk, crate::spend_frontier::cm_bytes_to_leaf(&self.deployer_id));
        let d4 = crate::spend_frontier::poseidon_pair(
            crate::spend_frontier::cm_bytes_to_leaf(&self.kc_commit),
            usdm_decider::poseidon2_compress::lanes_of(&[0x4434_4b43, u64::from(self.height_class)]),
        );
        crate::spend_frontier::poseidon_pair(base, d4)
    }

    /// The state leaf of this contract at `storage_root`.
    #[must_use]
    pub fn leaf(&self, storage_root: Digest4) -> Digest4 {
        contract_leaf(&self.code_id, self.digest(), storage_root)
    }
}

/// What the fold decided about a carried object of this class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeployApply {
    NotDeploy,
    /// The contract-state root the fold wrote.
    Applied(Digest4),
    Refused(&'static str),
}

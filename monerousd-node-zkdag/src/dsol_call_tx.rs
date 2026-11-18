// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ §BR-12 / DSOL door landing 2 — THE CALL DOOR, `Class::DsolCall` (byte 18; docs/DSOL-NODE-DOOR-SPEC.md §1–§4, §6b, §12 L2).
//!
//! A contract call is PROVEN by the caller's wallet (`dsol_cpu_air::prove_dsol_call_run`) and VERIFIED by every node — never
//! re-executed. The object carries the root call's statement, proof and effect list, every LIBRARY it ran (`LibCall`), the
//! code of each (the node stores no code), the contract's manifest and storage root before the call with the compact path
//! that places them in the ONE contract-state root, the caller's pseudonymous ML-DSA-65 key `pk_c` and its signature, and a
//! FEE SPEND: one USDm note whose public `out0` is the deployed PUBLISHER FEE, owned by the publisher's note key through an
//! opening that is a public function of this call (so every node recomputes the commitment and the publisher's wallet derives
//! the note from the chain), `out1` the change, the network fee welded on top. The fold, in canonical order, verifies the
//! state leaf against its root, every proof against its carried code, the chain's authorisation, the context digests, the
//! epoch, the fee, and writes the leaf with `storage_post` — the root contract's storage is the ONE leaf a call moves in L2.
//!
//! §9.6, answered: (1) PoW — the carrying block's, and the tx stamp; (2) proof — `verify_dsol_call` for the root and every
//! library against the code whose `blake3` is its `code_id`, `authorize_segment_chain` (one segment in L2) and
//! `authorize_call_chain_bound` (the node binds the root's `cid` through the state leaf; re-entry refused), the caller's
//! signature (A1), `tx_hash = H(fee nf)` (A2), `block_number` = the carrying block's epoch floor (A3), the fee carrier;
//! (3) value — a contract cannot mint: value moves only by the fee spend (conserved by its carrier) and by `Nullifier` effects
//! that retire tags on the lane; `Event` is bound by the proof and moves nothing; `Syscall` and plain `Call` are REFUSED in L2
//! (no node host re-derives a syscall yet; a plain callee would need its own leaf) — fail closed, named; (4) replay — own
//! nullifiers = the fee note's + every `Nullifier` effect tag, refused by the spent set; (5) bounded — one segment, ≤
//! [`DSOL_CALL_LIBRARIES_MAX`] libraries, ≤ [`DSOL_CALL_EFFECTS_MAX`] effects, code ≤ `DSOL_CODE_BYTES_MAX` each, one path;
//! (6) parity with the deploy door: every check it runs, plus the proofs, the context and the fee's publisher.
//!
//! THE PUBLISHER FEE, ENFORCED (bridge spec §10, "public rate, private payment"): the fee amount is the deploy's word (public by
//! the manifest the leaf binds), the payment is an ordinary note inside the caller's own transaction whose shape every other
//! note shares; its owner is the publisher's `spk` with the opening `owner_opening(spk, publisher_fee_seed(cid, tx_hash))`.
//! Stated: the seed is public, so an observer can tell "this note is the fee of this call" — exactly what the object already
//! says (which contract, which fee); the publisher's later SPEND is as unlinkable as any note's.
//!
//! ROOT-LAYER: the call is PRODUCED as one chain object and decided at the fold on every node from its bytes and the node's
//!   root; the wallet proves, the route publishes. MEASURED: the pins below — two nodes move one root and record the
//!   publisher's note from the block alone; a fee below the manifest, a forged caller, a wrong tx hash, a wrong epoch, a
//!   wrong storage root, a flipped proof, a replayed fee note and two calls on one contract in one block are each refused.
//! MUST-STAY-GREEN: every deploy pin (the leaf now binds the manifest; `contract_leaf` changed shape before any chain held one).
//!
//! BORROWED: a call is a transaction that pays its fee from its own input (Ethereum gas; Bitcoin inputs − outputs), the
//! account trie's leaf moves `storage_pre → storage_post` (Ethereum's state transition), two transactions on one account in
//! one block conflict (Ethereum's nonce shape), and a proven call is verified, never re-run (Aztec/zkSync validity rollups).
//! DIGITAL-CASH-PRIVACY-REVIEWED: which contract, its code, the fee amount, the caller's contract-scoped pseudonym and the
//! effect digests are public by the door's spec (§5); `argv`, intermediate values and the storage contents are not.

use crate::contract_state::{update_root, PathWire};
use crate::dsol_deploy_tx::{ContractManifest, DSOL_CODE_BYTES_MAX, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES};
use crate::spend_frontier::Digest4;
use usdm_decider::dsol_cpu_air::{DsolCallProof, DsolStatement, ProvenCall};
use usdm_decider::dsol_vm::Effect;

/// Libraries one call may run (each is one more proof the node verifies).
pub const DSOL_CALL_LIBRARIES_MAX: usize = 8;
/// Effects one segment may list (one effect costs at least one row of a ≤ 2^20-row table; this is the object's own bound).
pub const DSOL_CALL_EFFECTS_MAX: usize = 4_096;

/// One proven run: its statement, proof and the effect list the statement's `effects_digest` folds.
/// A3's validity window in epochs: a call's statement may name the carrying block's epoch or either of the two before it.
pub const DSOL_EPOCH_WINDOW: u64 = 3;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvenSegment {
    pub stmt: DsolStatement,
    /// O1-FOOTPRINT-REVIEWED: one call proof (tens of KB), the transaction itself, released with it.
    pub proof: DsolCallProof,
    /// O1-FOOTPRINT-REVIEWED: bounded by [`DSOL_CALL_EFFECTS_MAX`] (decode refuses more).
    pub effects: Vec<Effect>,
}

impl ProvenSegment {
    fn as_call(&self) -> ProvenCall<'_> {
        ProvenCall { proof: &self.proof, stmt: &self.stmt, effects: &self.effects }
    }
}

/// The call's fee spend: the deploy's publisher fee as a public `out0` owned by the publisher, the change as `out1`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallFee {
    pub nullifier: [u8; 32],
    pub leaf_commit: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: one bond-validity carrier (fixed size), released with the transaction.
    pub carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one note-membership step carrier (fixed size).
    pub membership_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: the fixed one-step tip.
    pub membership_tip: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one note payload (`PQ_NOTE_BYTES`, or its 64-byte carriage reference) — the publisher's fee note.
    pub publisher_note: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one note payload (or reference) — the caller's change.
    pub change_note: Vec<u8>,
    /// The change note's OLI clue (non-empty, ≤ `peg_in_tx::OWNER_CLUE_MAX`).
    pub change_clue: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsolCallTx {
    /// The contract called (the deploy's `cid`).
    pub cid: [u8; 32],
    /// The manifest the contract's state leaf binds — the node checks the leaf, so a caller cannot understate the fee.
    pub manifest: ContractManifest,
    /// The contract's storage root BEFORE this call (canonical digest bytes), as the leaf holds it.
    pub storage_pre: [u8; 32],
    /// The compact path of `cid` in the contract-state root this call was built on.
    pub state_path: PathWire,
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_PK_BYTES`] — the caller's contract-scoped pseudonym (A1).
    pub pk_c: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: exactly [`ML_DSA_65_SIG_BYTES`] — ML-DSA-65 over [`Self::signing_body`].
    pub sig: Vec<u8>,
    /// The root call (ONE segment in L2; continuations are L3).
    pub root: ProvenSegment,
    /// O1-FOOTPRINT-REVIEWED: ≤ [`DSOL_CALL_LIBRARIES_MAX`] — the libraries the root ran against its own storage (`LibCall`).
    pub libraries: Vec<ProvenSegment>,
    /// O1-FOOTPRINT-REVIEWED: `1 + libraries.len()` programs of ≤ `DSOL_CODE_BYTES_MAX` each — the root's code first.
    pub code: Vec<Vec<u8>>,
    pub fee: CallFee,
    /// D4 — what this call wrote, carried so the contract never depends on anyone keeping it (§8 A4): the blob of
    /// `W(class)` entries encrypted under the deployed key, the salt fresh to this proof (H1), and the proof that the blob
    /// is a write-set taking `storage_pre` to `storage_post` under the key the leaf commits.
    pub storage: StorageBlob,
}

/// D4 — a call's storage blob and its proof (`usdm_decider::dsol_blob_air`): the contract's WHOLE post-state, every slot
/// a write from the empty trie, sealed under the contract's key. The blob has the class's constant `W(h)` entries
/// whatever the state holds, so carrying the whole state costs a call nothing over carrying what it changed, and the
/// newest call of a contract IS its state (`contract_blobs`): a reader decrypts one record, never a history. A contract's
/// storage therefore holds at most `W(h)` slots (33 at class 14, 132 at 16); a call that would grow it past them does
/// not prove, and a back end that needs more is split across contracts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct StorageBlob {
    /// Fresh per proof: two proofs of one call never share a keystream.
    pub salt: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: exactly `entries_for_class(class) × ENTRY_BYTES` (decode refuses any other length).
    pub blob: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one blinded chained proof (A-F55: the direct engine did not bind its opened row), bounded by
    /// [`STORAGE_PROOF_BYTES_MAX`].
    pub proof: Vec<u8>,
}

/// The most bytes a blob proof may take on the wire: the decider's carrier budget.
pub const STORAGE_PROOF_BYTES_MAX: usize = 1_800_000;

/// The public seed of a call's publisher-fee note: `blake3("USDMD-DSOL-PUBLISHER-FEE-SEED-v1" ‖ cid ‖ tx_hash)` as a leaf.
#[must_use]
pub fn publisher_fee_seed(cid: &[u8; 32], tx_hash: &[u8; 32]) -> Digest4 {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-DSOL-PUBLISHER-FEE-SEED-v1");
    h.update(cid);
    h.update(tx_hash);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// The publisher-fee note's OPENING: the publisher's `spk` with the call's public seed (`owner_opening`, the one spelling
/// every note's owner uses). `None` when the manifest's spk bytes are not a canonical digest.
#[must_use]
pub fn publisher_fee_opening(publisher_spk: &[u8; 32], cid: &[u8; 32], tx_hash: &[u8; 32]) -> Option<Digest4> {
    let spk = crate::spend_frontier::cm_bytes_to_root(publisher_spk)?;
    Some(usdm_decider::whir_rec_block::owner_opening(&spk, &publisher_fee_seed(cid, tx_hash)))
}

/// The commitment the call's fee `out0` MUST be: the deployed fee, USDm, to the publisher.
#[must_use]
pub fn publisher_fee_cm(manifest: &ContractManifest, cid: &[u8; 32], tx_hash: &[u8; 32]) -> Option<Digest4> {
    let opening = publisher_fee_opening(&manifest.publisher_spk, cid, tx_hash)?;
    Some(usdm_decider::whir_rec_block::asset_note_cm(manifest.fee(), usdm_decider::whir_rec_block::USDM_ASSET_TAG, opening))
}

impl DsolCallTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DsolCall, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode with every bound checked (§9.6 #5) — anything outside them came from no honest wallet.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<DsolCallTx> {
        let t: DsolCallTx = crate::chain_object::decode_exact(bytes)?;
        if t.pk_c.len() != ML_DSA_65_PK_BYTES || t.sig.len() != ML_DSA_65_SIG_BYTES {
            return None;
        }
        if t.libraries.len() > DSOL_CALL_LIBRARIES_MAX || t.code.len() != 1 + t.libraries.len() {
            return None;
        }
        if t.code.iter().any(|c| c.is_empty() || c.len() > DSOL_CODE_BYTES_MAX) {
            return None;
        }
        if t.root.effects.len() > DSOL_CALL_EFFECTS_MAX || t.libraries.iter().any(|l| l.effects.len() > DSOL_CALL_EFFECTS_MAX) {
            return None;
        }
        if t.root.stmt.height_log2 > usdm_decider::dsol_cpu_air::MAX_HEIGHT_LOG2 {
            return None;
        }
        if t.state_path.sibs.len() > crate::contract_state::DEPTH || t.state_path.expand().is_none() {
            return None;
        }
        if crate::spend_frontier::cm_bytes_to_root(&t.storage_pre).is_none() {
            return None;
        }
        // D4: the blob is exactly the class's entries, and the proof within the carrier budget (§9.6 #5)
        let class = t.root.stmt.height_log2;
        if t.storage.blob.len() != usdm_decider::dsol_blob_air::entries_for_class(class) * usdm_decider::dsol_blob_air::ENTRY_BYTES
            || t.storage.proof.is_empty()
            || t.storage.proof.len() > STORAGE_PROOF_BYTES_MAX
        {
            return None;
        }
        let f = &t.fee;
        if f.carrier.is_empty() || f.membership_carrier.is_empty() || f.membership_tip.is_empty() {
            return None;
        }
        if f.change_clue.is_empty() || f.change_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return None;
        }
        for n in [&f.publisher_note, &f.change_note] {
            if n.len() != crate::cover::PQ_NOTE_BYTES && n.len() != 64 {
                return None;
            }
            if crate::spend_frontier::note_cm_of(n).is_none() {
                return None;
            }
        }
        if crate::spend_frontier::cm_bytes_to_root(&f.nullifier).is_none() || crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit).is_none() {
            return None;
        }
        Some(t)
    }

    /// A2 — `tx_hash = H("dsol-tx", fee nf)`: known before proving, unique by the nullifier set.
    #[must_use]
    pub fn tx_hash(&self) -> [u8; 32] {
        usdm_decider::dsol_vm::dsol_tx_hash(&self.fee.nullifier)
    }

    /// The bytes the caller signs: the object with the signature emptied and both carried notes reduced to their 32-byte
    /// commitments (the carried form rewrites a note to its 64-byte reference — the deploy door's finding).
    #[must_use]
    pub fn signing_body(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig = Vec::new();
        for n in [&mut unsigned.fee.publisher_note, &mut unsigned.fee.change_note] {
            if n.len() >= 32 {
                n.truncate(32);
            }
        }
        let mut pre = Vec::with_capacity(32 + unsigned.encode().len());
        pre.extend_from_slice(b"USDMD-DSOL-CALL-SIG-v1");
        pre.extend_from_slice(&unsigned.encode());
        pre
    }

    /// A1 — the carried `pk_c` signs the object.
    #[must_use]
    pub fn signature_verifies(&self) -> bool {
        crate::pqauth::ml_dsa_verify(&self.signing_body(), &self.pk_c, &self.sig)
    }

    /// The statement's CONTEXT is the carried bytes' (A1 caller/subaddress, A2 tx hash, the cid, the root code's identity) —
    /// every value the machine landed, re-derived here from public bytes through the same functions the wallet used.
    #[must_use]
    pub fn context_matches(&self) -> bool {
        use usdm_decider::dsol_vm::{dsol_caller_subaddress, dsol_caller_wallet, str_digest};
        let (Some(caller), Some(sub)) = (dsol_caller_wallet(&self.pk_c), dsol_caller_subaddress(&self.pk_c)) else {
            return false;
        };
        let s = &self.root.stmt;
        s.cid == str_digest(&self.cid)
            && s.caller == str_digest(&caller)
            && s.subaddress == str_digest(&sub)
            && s.tx_hash == str_digest(&self.tx_hash())
            && s.code_id == *blake3::hash(&self.code[0]).as_bytes()
            && s.code_id == self.manifest.code_id
            && crate::spend_frontier::cm_bytes_to_root(&self.storage_pre) == Some(s.storage_pre)
    }

    /// A3 — the statement's `block_number` is the EPOCH FLOOR of the carrying block's blue score, or of one of the
    /// [`DSOL_EPOCH_WINDOW`] − 1 epochs before it: a call proven in epoch `e` is valid when carried in `e`, `e + 1` or `e + 2`
    /// (a transaction's validity window — Solana's recent-blockhash bound of ~60–90 s; Bitcoin's nLockTime is a bound, never an
    /// exact height). MEASURED 2026-11-01 (the F13 layer-2 journey, g4/h6-f13-journey.log): with the exact rule a call the
    /// shipped wallet proved and relayed landed in a LATER 64-block epoch (32 s at 500 ms blocks) and was refused on every
    /// node; one WHIR proof at height class 14 took ~60 s of wall clock on a loaded machine (`[zerocheck-progress]`), so a
    /// one-epoch window would still fail an honest phone. A FUTURE epoch (a statement above the carrying block's floor) and
    /// anything three or more epochs stale stay refused, so a contract's `BLOCK_NUMBER` is the proving epoch's floor, at most
    /// two epochs (128 blocks, 64 s) behind its block — epoch granularity it already had. ROOT-LAYER: the one epoch rule,
    /// read by the fold door for every call.
    /// MUST-STAY-GREEN: `dsol_a_call_paying_less_…` ("built for the next epoch" refused); the window pin.
    #[must_use]
    pub fn epoch_matches(&self, carrying_blue: u64) -> bool {
        let c = crate::dsol::dsol_block_number(carrying_blue);
        let b = self.root.stmt.block_number;
        (0..DSOL_EPOCH_WINDOW).any(|k| b.checked_add(k * crate::oli::EPOCH_BLOCKS) == Some(c))
    }

    /// The code whose `blake3` is `code_id`, among the carried programs.
    fn code_of(&self, code_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.code.iter().find(|c| *blake3::hash(c).as_bytes() == *code_id).cloned()
    }

    /// L2's effect policy — fail closed on what no door applies yet: a `Syscall` (no node host re-derives one) or a plain
    /// `Call` (a callee's own leaf). `Nullifier`, `Event`, `PrivateSlot` and `LibCall` are applied or authorised.
    #[must_use]
    pub fn effects_applicable(&self) -> bool {
        let ok = |e: &Effect| !matches!(e, Effect::Syscall { .. } | Effect::Call { .. });
        self.root.effects.iter().all(ok) && self.libraries.iter().all(|l| l.effects.iter().all(ok))
    }

    /// The decider's whole verdict over the carried proofs: the root's segment (one), its libraries (each proof against its
    /// own carried code, each `LibCall` effect matched exactly once, re-entry refused), with the root's identity BOUND to the
    /// `cid` the state leaf names.
    #[must_use]
    pub fn chain_authorised(&self) -> bool {
        let code_of = |id: &[u8; 32]| self.code_of(id);
        let resolve = |d: &Digest4| -> Option<[u8; 32]> {
            self.code.iter().map(|c| *blake3::hash(c).as_bytes()).find(|id| usdm_decider::dsol_vm::str_digest(id) == *d)
        };
        let root = self.root.as_call();
        let libs: Vec<ProvenCall<'_>> = self.libraries.iter().map(ProvenSegment::as_call).collect();
        usdm_decider::dsol_cpu_air::authorize_segment_chain(std::slice::from_ref(&root), &code_of)
            && usdm_decider::dsol_cpu_air::authorize_call_chain_bound(&root, &libs, &code_of, &resolve, &usdm_decider::dsol_vm::str_digest(&self.cid))
    }

    /// The fee carrier proves: one USDm note spent, `out0` = exactly the deployed publisher fee into the publisher's note
    /// commitment for THIS call, `out1` the change, the network fee welded; and the carried publisher note IS that commitment.
    #[must_use]
    pub fn fee_carrier_verifies(&self) -> bool {
        let f = &self.fee;
        let (Some(nf), Some(lc), Some(change), Some(pub_note_cm), Some(want)) = (
            crate::spend_frontier::cm_bytes_to_root(&f.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&f.leaf_commit),
            crate::spend_frontier::note_cm_of(&f.change_note),
            crate::spend_frontier::note_cm_of(&f.publisher_note),
            publisher_fee_cm(&self.manifest, &self.cid, &self.tx_hash()),
        ) else {
            return false;
        };
        pub_note_cm == want
            && usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
                &f.carrier,
                want,
                change,
                nf,
                self.manifest.fee(),
                lc,
                usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
            )
    }

    /// D4 — the statement the call's storage blob must prove, rebuilt from PUBLIC values alone: the empty trie and the
    /// call's post-state root, its tx hash, the salt it carries, and the key commitment and class the contract's LEAF holds (the leaf is checked
    /// against the chain's root by the fold, so a call cannot name another key).
    #[must_use]
    pub fn blob_statement(&self) -> Option<usdm_decider::dsol_blob_air::BlobStatement> {
        use usdm_decider::dsol_blob_air as b;
        let class = self.root.stmt.height_log2;
        Some(b::BlobStatement {
            // the whole state: from the empty trie to the call's post-state
            storage_pre: crate::dsol_deploy_tx::empty_storage_root(),
            storage_post: self.root.stmt.storage_post,
            tx_hash: usdm_decider::dsol_vm::str_digest(&self.tx_hash()),
            blob_salt: usdm_decider::poseidon2_compress::hash32_to_digest(&self.storage.salt),
            kc_commit: crate::spend_frontier::cm_bytes_to_root(&self.manifest.kc_commit)?,
            blob_digest: b::blob_digest(&self.storage.blob)?,
            entries: b::entries_for_class(class),
            height_log2: b::blob_height_log2(class),
        })
    }

    /// D4 + D6 — the call runs at its contract's ONE class, and its blob proves it rebuilds the call's post-state under the
    /// deployed key. A garbage blob beside an honest `storage_post`, a blob that leaves a write out, another key, another
    /// salt or another entry count is refused here (`dsol_blob_air`'s lying-prover gates).
    #[must_use]
    pub fn storage_blob_verifies(&self) -> bool {
        let class = self.root.stmt.height_log2;
        if class != self.manifest.height_class {
            return false;
        }
        let Some(stmt) = self.blob_statement() else { return false };
        usdm_decider::dsol_blob_air::verify_blob(&usdm_decider::dsol_blob_air::BlobProof { bytes: self.storage.proof.clone() }, &stmt, &self.storage.blob, class)
    }

    /// The pool door's whole stateless verdict (the state leaf, the fee note's membership and the epoch are the fold's).
    #[must_use]
    pub fn self_authorised(&self) -> Option<&'static str> {
        if !self.signature_verifies() {
            return Some("the caller's signature does not verify");
        }
        if !self.context_matches() {
            return Some("the statement's context is not the carried bytes' (caller, tx hash, cid, code or storage root)");
        }
        if !self.effects_applicable() {
            return Some("the call lists an effect no door applies yet (a syscall or a plain callee call)");
        }
        if !self.fee_carrier_verifies() {
            return Some("its fee spend does not pay the deployed publisher fee to the publisher (or the network fee)");
        }
        if !self.chain_authorised() {
            return Some("a call proof does not verify against its carried code, or the call chain is not authorised");
        }
        if !self.storage_blob_verifies() {
            return Some("its storage blob does not prove the call's post-state under the deployed key, or the call is not at its contract's class");
        }
        None
    }

    /// The object's own lane tags: the fee note's nullifier and every `Nullifier` effect the root and its libraries emitted.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        let mut out = vec![self.fee.nullifier];
        for seg in std::iter::once(&self.root).chain(self.libraries.iter()) {
            for e in &seg.effects {
                if let Effect::Nullifier { tag } = e {
                    out.push(crate::spend_frontier::leaf_to_cm_bytes(*tag));
                }
            }
        }
        out
    }

    /// The contract-state root after this call, from `root`: the leaf `(code, manifest, storage_pre)` must sit at `cid`, and
    /// moves to `(code, manifest, storage_post)`. `None` = the path does not open `root` (the leaf moved — another call landed
    /// first — or the carried pre-state is not the chain's).
    #[must_use]
    pub fn root_after(&self, root: Digest4) -> Option<Digest4> {
        let sibs = self.state_path.expand()?;
        let pre = crate::spend_frontier::cm_bytes_to_root(&self.storage_pre)?;
        update_root(root, &self.cid, self.manifest.leaf(pre), self.manifest.leaf(self.root.stmt.storage_post), &sibs)
    }
}

/// What the fold decided about a carried object of this class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallApply {
    NotCall,
    Applied(Digest4),
    Refused(&'static str),
}

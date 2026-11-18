// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ AUDIT FINDING F15 (2026-11-10) — THE PAID DIRECTORY ENTRY, `Class::DirEntry`.
//!
//! WHAT WAS WRONG (read in the code, then shown on real nodes by `scratchpad/net/dir_priced.py`). A directory sign-up (a
//! @username, a group handle, a profile with a picture, a username handover) reached every node's PERMANENT state on its
//! signature alone: `Node::submit_dir_entry_verdict` checked the ML-DSA signature and queued it, the producer sealed its
//! queue into the block's directory sidecar with no size bound (`pad_sidecar_to_constant` leaves a sidecar over
//! 16,384 bytes as it is), and every node kept every applied entry for ever. A key holding nothing could write about
//! 37 KB (a 32,000-byte profile, its key and its signature) into every node, as often as it liked: unbounded growth of
//! node state at no cost, on a chain whose cardinal is NO GROWTH ON ANY AXIS.
//!
//! THE SHAPE, BORROWED: a write that every node keeps is a TRANSACTION that pays for its bytes from its own input
//! (Bitcoin: fee by size; Ethereum: gas per byte of storage; ENS: a name is registered by a paying transaction). So a
//! directory entry reaches the chain only inside this object: the signed entry exactly as the directory applies it, and
//! a USDm BURN of the entry's price (`CreationFee`, the one carrier an asset creation and a contract deploy already pay
//! with), whose destroyed output is bound to THIS entry's bytes. The fold applies the entry in canonical order on every
//! node. The unpaid sidecar path is closed: a block's directory sidecar carries nothing, so it is the constant cover pad.
//!
//! THE PRICE is a public function of the bytes every node will keep: [`DIR_ENTRY_FEE_ATOMIC`] an entry plus
//! [`DIR_KB_FEE_ATOMIC`] for each started kilobyte of the entry's wire form. It goes to the chain's four fee pools at the
//! fold, like a creation's. Derivation, not a tuned number: one gigabyte of node state is 2^20 kilobytes, so filling one
//! costs a spammer at least 2^20 × 0.01 = 10,485 USDm, while a @username (measured wire size: see
//! `a_username_and_a_full_profile_cost_what_their_bytes_cost`) stays under a dime and a profile with the largest picture
//! the directory admits stays under half a dollar.
//!
//! WHAT A CLAIM THAT LOSES COSTS. An entry the pool door can see will not be written (the name is taken, it changes
//! nothing) is refused before anything is carried, and costs nothing. An entry that IS carried and valid burns its fee
//! whether or not the directory then writes it: two claims for one name inside the fold's lag are both carried, one
//! gets the name, the other pays its fee and gets none (the fold door,
//! `node::objects::dir_entry_tx::apply_chain_dir_entry`, says why this replaced "a refused
//! entry costs nothing": on real nodes the fold's refused-object path retired the loser's whole note, hole A-F22).
//! An entry that is not valid (a signature that does not verify, a burn that is not its price, a fee note whose
//! membership does not verify at the fold) is refused on the item.
//!
//! NO RE-CARRY LANE. The old path kept applied entries in a node-local queue to carry them again after a sync adopt
//! (`dir_reset_for_refill_recarry`): process-local state standing in for the chain. A paid entry is a transaction, so
//! it has a transaction's liveness: the object stays in the pool until a block carries it, and the wallet that made it
//! sends the same bytes again until the chain holds the entry (the object is its own receipt: once its fee note is
//! spent it has applied, and the spent set refuses a second apply).
//!
//! §9.6, answered (the door this parallels is `Class::DsolDeploy`, the latest fee-burning object):
//! (1) proof of work: the carrying block's, at the block doors, and the tx stamp like every pooled object;
//! (2) proofs: the entry's ML-DSA-65 signature over `directory::dir_register_msg` and the profile's address binding
//!     (`self_authorised`, at the pool door and again at the fold), and the fee burn's bond-validity carrier
//!     (`fee_carrier_verifies`) with the burned note's membership through the one fee-burn door
//!     (`Node::burn_fee_refusal`, Admit at the publisher, Fold on every node);
//! (3) value: the burn destroys exactly the price into a commitment no key opens (credited to the four fee pools at the
//!     fold), nothing is minted, the change is the carrier's own `out1`;
//! (4) replay: the object's own lane tag is the fee note's nullifier, refused a second time by the spent set;
//! (5) bounded work: one signature check, one carrier, one member step; the entry's wire form is at most
//!     [`DIR_ENTRY_BYTES_MAX`], refused at decode before any verify;
//! (6) parity with `DsolDeploy`: decode bounds, signature, fee carrier, membership at both doors, fold-decided (never at
//!     graft, in arrival order: DB-274), change note recorded from the object, the fee summed for the pools. It has no
//!     state path (the directory is keyed, not a tree) and no one-time id (the fee nullifier is the object's identity).
//! (7) scale (SAFE AT SCALE): with the nodes that bond, NOTHING grows: no validator signs, carries or counts anything per
//!     entry or per bonded node, and the object has one signer, its owner. With users and items in flight: one pooled
//!     object per entry (at most [`DIR_ENTRY_BYTES_MAX`] plus one carrier of the creation's fixed shape), gossiped once
//!     like any transaction; a block carries only what its producer pooled. With height: nothing; node state grows by
//!     an entry's bytes per PAID entry and by nothing else, which is the growth the price is set against.
//! (8) what protects it (AI RESISTANT): the value side is (a), a PROOF every node checks: the fee note's spend carrier,
//!     its membership and the burn commitment bound to this entry's id; an entry cannot be written without that proof
//!     passing, and it creates no value (it only burns). Who owns a name is (b), ordinary code: first come in the
//!     chain's one fold order, the entry's own ML-DSA-65 signature naming its owner; breaking that rule could mis-assign
//!     a name and never reach a note (a name moves no money: a payment to a name is answered by the owner's own wallet).
//!     There is no (c): no key, operator or machine can write, remove or reorder an entry. No (d) beyond the chain's own.
//!
//! ROOT-LAYER: the entry is PRODUCED into the chain as one object here and decided at the fold on every node; the wallet
//!   only builds it and the route only publishes it.
//! MEASURED: the pins below and the real-node check `dir-priced` (RED on the tree before this module: an empty wallet's
//!   20,000-character profile reached the other node).
//! MUST-STAY-GREEN: every directory pin (`apply_dir_set_folds_a_signed_signup_and_refuses_forgery_and_theft`, the DB-274
//!   two-order pin, the refill pins), the real-node checks `names` and `pay-name`, every `AssetCreate` and `DsolDeploy`
//!   pin (their doors are untouched; the burn door they share is called, not changed).
//!
//! Cons, quantified: a sign-up now needs a funded wallet (a @username costs under a dime, shown in dollars before the
//! user confirms) and one burn proof (the creation's carrier: the same seconds a token creation takes); the object adds
//! its carrier (the creation's constant) to the block that carries it, where the unpaid entry added none.
//! DIGITAL-CASH-PRIVACY-REVIEWED: an entry is data its owner chose to publish (as before); the burn's amount is the
//! public price of the entry's public size; the change is an ordinary confidential note; the paying note is hidden by
//! the carrier like any spend, so a name is not linked to the note that paid for it.

use crate::asset_tx::CreationFee;
use crate::directory::DirEntry;
use crate::spend_frontier::Digest4;

/// The fixed part of an entry's price: 0.01 USDm.
pub const DIR_ENTRY_FEE_ATOMIC: u64 = 1_000_000;
/// The price of each started kilobyte (1,024 bytes) of the entry's wire form: 0.01 USDm.
pub const DIR_KB_FEE_ATOMIC: u64 = 1_000_000;
/// ML-DSA-65's verification key and signature sizes (the directory's one signature scheme).
pub const ML_DSA_65_PK_BYTES: usize = crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES;
pub const ML_DSA_65_SIG_BYTES: usize = crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES;
/// The largest wire form an entry may have: the largest profile topic the directory admits, an ML-DSA-65 key and
/// signature, and room for the key, the address and the name. An entry past it came from no honest wallet.
pub const DIR_ENTRY_BYTES_MAX: usize = crate::directory::PROFILE_TOPIC_MAX + ML_DSA_65_PK_BYTES + ML_DSA_65_SIG_BYTES + 8 * 1024;

/// ⭐ THE PRICE OF KEEPING `wire_len` BYTES IN EVERY NODE FOR EVER: the fixed part plus each started kilobyte.
#[must_use]
pub fn dir_entry_fee_atomic(wire_len: usize) -> u64 {
    let kb = u64::try_from(wire_len.div_ceil(1024)).unwrap_or(u64::MAX);
    DIR_ENTRY_FEE_ATOMIC.saturating_add(DIR_KB_FEE_ATOMIC.saturating_mul(kb))
}

/// One directory entry and the burn that pays for it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirEntryTx {
    /// The signed entry, exactly as the directory applies it (`Node::apply_dir_entry_at_fold`).
    pub entry: DirEntry,
    /// The fee burn: the asset creation's shape, with `out0 = dir_burn_cm(entry_id, price)`.
    pub fee: CreationFee,
    /// ⭐ THE BYTES OF THE PICTURE THE ENTRY NAMES (a collection's cover; spec §12.6), or empty when it names none. The
    /// entry holds only the picture's digest (`DirEntry::pic`), which its signature covers and which this object's burn
    /// is bound to through the entry's id; `decode` refuses bytes that do not hash to it. Nodes keep the bytes by that
    /// digest, apart from the certified directory sequence (`Directory::keep_pic`), and they are paid for here by the
    /// kilobyte ([`Self::price`]).
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant (`directory::COLLECTION_COVER_MAX`), released with the object.
    pub art: Vec<u8>,
}

/// The identity of an entry for its burn: every byte of its wire form, signature included, so a burn proven for one
/// entry pays for no other.
#[must_use]
pub fn dir_entry_id(entry_wire: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-DIR-ENTRY-ID-v1");
    h.update(entry_wire);
    *h.finalize().as_bytes()
}

/// The opening of an entry's destroyed fee output: a public function of the entry's id (the creation burn's shape).
#[must_use]
pub fn dir_burn_opening(entry_id: &[u8; 32]) -> Digest4 {
    let mut pre = Vec::with_capacity(32 + 32);
    pre.extend_from_slice(b"USDMD-DIR-ENTRY-FEE-BURN-v1");
    pre.extend_from_slice(entry_id);
    crate::spend_frontier::cm_bytes_to_leaf(crate::hash::Hash32::hash(&pre).as_bytes())
}

/// The commitment the entry's fee burn MUST destroy.
#[must_use]
pub fn dir_burn_cm(entry_id: &[u8; 32], price: u64) -> Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(price, usdm_decider::whir_rec_block::USDM_ASSET_TAG, dir_burn_opening(entry_id))
}

impl DirEntryTx {
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DirEntry, &self.encode())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode with every bound checked: an object outside them came from no honest wallet and is refused here, before
    /// any verify (§9.6 #5).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<DirEntryTx> {
        let t: DirEntryTx = crate::chain_object::decode_exact(bytes)?;
        let e = &t.entry;
        // ⛔ THE KINDS A PERSON MAY SIGN UP: a @username, a group handle, a profile, a handover, a collection. An ASSET'S
        // record is not among them: only its creation's own fold writes one (`directory::KIND_ASSET`).
        if e.kind > crate::directory::KIND_COLLECTION {
            return None;
        }
        // a picture is named by a collection (its cover) and by no other sign-up; the bytes ride this object beside the
        // entry, are exactly the bytes the entry's digest names, and are bounded in size and format, before any verify
        if e.kind == crate::directory::KIND_COLLECTION {
            if e.topic.len() > crate::directory::COLLECTION_TEXT_MAX || e.name.len() > crate::directory::COLLECTION_TITLE_MAX {
                return None;
            }
        } else if e.pic.is_some() {
            return None;
        }
        match e.pic {
            None if !t.art.is_empty() => return None, // bytes no entry names
            None => {}
            Some(digest) => {
                if t.art.is_empty()
                    || !crate::directory::art_ok(&t.art, crate::directory::COLLECTION_COVER_MAX)
                    || *blake3::hash(&t.art).as_bytes() != digest
                {
                    return None; // a named picture arrives with its own bytes, or the object is not an entry
                }
            }
        }
        if e.pubkey.len() != ML_DSA_65_PK_BYTES || e.sig.len() != ML_DSA_65_SIG_BYTES {
            return None;
        }
        if e.key.is_empty() || e.topic.len() > crate::directory::PROFILE_TOPIC_MAX {
            return None;
        }
        let wire_len = e.to_wire().len();
        if wire_len == 0 || wire_len > DIR_ENTRY_BYTES_MAX {
            return None;
        }
        let f = &t.fee;
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
        Some(t)
    }

    /// The entry's id: what its burn is bound to.
    #[must_use]
    pub fn entry_id(&self) -> [u8; 32] {
        dir_entry_id(&self.entry.to_wire())
    }

    /// What this entry costs: a public function of the bytes every node is asked to keep for it, the entry's own wire
    /// form and the picture it names.
    #[must_use]
    pub fn price(&self) -> u64 {
        dir_entry_fee_atomic(self.entry.to_wire().len().saturating_add(self.art.len()))
    }

    /// Does the entry's own key sign it, and (for a profile) is that key the address's own? The directory's two
    /// stateless checks, the same the fold's apply runs.
    #[must_use]
    pub fn entry_verifies(&self) -> bool {
        let e = &self.entry;
        // the one message every verifier builds (`directory::dir_entry_msg`): it covers a collection cover's digest
        let msg = crate::directory::dir_entry_msg(e);
        crate::pqauth::ml_dsa_verify(&msg, &e.pubkey, &e.sig) && crate::directory::profile_binding_ok(e)
    }

    /// Does the fee burn's carrier prove: one USDm note is spent, `out0` destroys exactly this entry's price into THIS
    /// entry's burn commitment, `out1` is the change, and the network fee is welded on top? Stateless (the creation's
    /// `fee_carrier_verifies`, with the entry's own burn commitment).
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
        let price = self.price();
        usdm_decider::verify_bond_validity_carrier_with_commit_bytes(
            &f.carrier,
            dir_burn_cm(&self.entry_id(), price),
            change,
            nf,
            price,
            lc,
            usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC,
        )
    }

    /// The pool door's whole stateless verdict: the entry's signature and binding, and the fee carrier (the bounds were
    /// decode's).
    #[must_use]
    pub fn self_authorised(&self) -> bool {
        self.entry_verifies() && self.fee_carrier_verifies()
    }

    /// The object's own lane tag: the fee note's nullifier (§9.6 #4).
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        vec![self.fee.nullifier]
    }
}

/// What the fold did with a blob offered to this class.
#[derive(Debug, PartialEq, Eq)]
pub enum DirEntryApply {
    /// Not this class's object.
    NotDirEntry,
    /// The entry is in the directory and its fee is burned.
    Applied,
    /// The entry is valid and paid, its fee is burned and its change recorded, and the directory did not write it: the
    /// name is another owner's (a claim that lost a race) or it changes nothing. See the fold door,
    /// `crate::node::objects::dir_entry_tx::apply_chain_dir_entry`.
    Paid,
    /// Refused on the item only (the block stands): not an entry, a signature or binding that does not verify, a burn
    /// that is not this entry's price, or a fee note whose membership does not verify at this fold. The reason is
    /// returned to the fold's dispatcher and nothing is written anywhere for a refusal.
    Refused(&'static str),
}

// THE FOLD DOOR of this class takes the node, so it lives with the node: `crate::node::objects::dir_entry_tx::apply_chain_dir_entry`
// (the node split, stage A: an object module never reaches up into the node). The two test helpers that drive a node
// (`fund_dir_fee_note_for_test`, `paid_dir_entry_for_test`) live there too.

/// TEST — the payer's fee-burn witness for `entry` (tag-seeded keys): out0 = exactly the entry's price into the entry's own
/// burn opening (the asset creation's `creation_fee_witness_for_test`, with the directory's price and opening).
#[cfg(test)]
pub fn dir_fee_witness_for_test(entry: &DirEntry, tag: u64) -> usdm_decider::whir_rec_block::SpendValidityWitness {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};
    let wire = entry.to_wire();
    let price = dir_entry_fee_atomic(wire.len());
    let value_in = price + PROTOCOL_FEE_ATOMIC + 70_000_000;
    SpendValidityWitness {
        value_in,
        owner: NoteOwner::from_test_key(lanes_of(&[0xd1ee, tag, 1, 2])),
        value_out: value_in - PROTOCOL_FEE_ATOMIC,
        fee: PROTOCOL_FEE_ATOMIC,
        lc_blind: lanes_of(&[0xd1ee, tag, 3, 3]),
        out0_value: price,
        out0_opening: dir_burn_opening(&dir_entry_id(&wire)),
        out1_value: value_in - PROTOCOL_FEE_ATOMIC - price,
        out1_opening: lanes_of(&[0xd1ee, tag, 4, 4]),
    }
}

#[cfg(test)]
mod dir_entry_tx_tests {
    use super::*;

    fn entry(kind: u8, key: &str, topic_len: usize) -> DirEntry {
        DirEntry {
            kind,
            key: key.to_string(),
            address: "a".repeat(120),
            name: String::new(),
            topic: "t".repeat(topic_len),
            pubkey: vec![7u8; ML_DSA_65_PK_BYTES],
            sig: vec![9u8; ML_DSA_65_SIG_BYTES],
            pic: None,
        }
    }

    /// The price follows the bytes: every started kilobyte is paid, no entry is free, an absurd size saturates, and a
    /// gigabyte of node state costs a spammer more than ten thousand dollars.
    #[test]
    fn the_price_is_the_fixed_part_plus_every_started_kilobyte() {
        assert_eq!(dir_entry_fee_atomic(0), DIR_ENTRY_FEE_ATOMIC, "no entry is free");
        assert_eq!(dir_entry_fee_atomic(1), DIR_ENTRY_FEE_ATOMIC + DIR_KB_FEE_ATOMIC);
        assert_eq!(dir_entry_fee_atomic(1024), DIR_ENTRY_FEE_ATOMIC + DIR_KB_FEE_ATOMIC);
        assert_eq!(dir_entry_fee_atomic(1025), DIR_ENTRY_FEE_ATOMIC + 2 * DIR_KB_FEE_ATOMIC);
        assert!(dir_entry_fee_atomic(DIR_ENTRY_BYTES_MAX) > dir_entry_fee_atomic(DIR_ENTRY_BYTES_MAX - 1024), "a larger entry costs more");
        // one gigabyte, written as the largest entries the directory admits
        let entries_per_gb = ((1usize << 30) / DIR_ENTRY_BYTES_MAX) as u128;
        let cost = u128::from(dir_entry_fee_atomic(DIR_ENTRY_BYTES_MAX)) * entries_per_gb;
        assert!(cost >= 10_000 * 100_000_000, "a gigabyte of directory costs at least 10,000 USDm, got {cost} atomic");
        assert_eq!(dir_entry_fee_atomic(usize::MAX), u64::MAX, "an absurd size saturates, never wraps to a low price");
    }

    /// What real entries cost, from their real wire sizes (an ML-DSA-65 key and signature are 5,261 bytes by
    /// themselves): a @username is under a dime and the largest profile is under half a dollar.
    #[test]
    fn a_username_and_a_full_profile_cost_what_their_bytes_cost() {
        let name = entry(crate::directory::KIND_NAME, "alice", 0);
        let profile = entry(crate::directory::KIND_PROFILE, &"a".repeat(120), crate::directory::PROFILE_TOPIC_MAX);
        let (n, p) = (name.to_wire().len(), profile.to_wire().len());
        assert!(n > ML_DSA_65_PK_BYTES + ML_DSA_65_SIG_BYTES && n < 6 * 1024, "a username's wire form is {n} bytes");
        assert!(dir_entry_fee_atomic(n) < 10_000_000, "a username costs under a dime, got {} atomic", dir_entry_fee_atomic(n));
        assert!(p <= DIR_ENTRY_BYTES_MAX, "the largest honest profile ({p} bytes) fits the bound");
        assert!(dir_entry_fee_atomic(p) < 50_000_000, "the largest profile costs under half a dollar, got {} atomic", dir_entry_fee_atomic(p));
    }

    /// A burn is bound to every byte of its entry: one changed byte anywhere (the name, the address, the picture, the
    /// signature) is a different id and a different burn commitment, so a burn cannot be lifted onto another entry, and
    /// a price proven for a small entry cannot pay for a large one.
    #[test]
    fn a_burn_is_bound_to_every_byte_of_its_entry_and_to_its_price() {
        let e = entry(crate::directory::KIND_PROFILE, "k", 300);
        let id = dir_entry_id(&e.to_wire());
        let price = dir_entry_fee_atomic(e.to_wire().len());
        let cm = dir_burn_cm(&id, price);
        let tampers: [(&str, fn(&mut DirEntry)); 5] = [
            ("the key", |x| x.key.push('x')),
            ("the address", |x| x.address.push('x')),
            ("the topic", |x| x.topic.push('x')),
            ("the signature", |x| x.sig[0] ^= 1),
            ("the signer's key", |x| x.pubkey[0] ^= 1),
        ];
        for (what, tamper) in tampers {
            let mut x = e.clone();
            tamper(&mut x);
            let xid = dir_entry_id(&x.to_wire());
            assert_ne!(xid, id, "a change to {what} kept the entry's id");
            assert_ne!(dir_burn_cm(&xid, price), cm, "a change to {what} kept the burn commitment");
        }
        assert_ne!(dir_burn_cm(&id, price + 1), cm, "the price is bound into the burn");
    }

    /// The decode refuses what no honest wallet sends, before any signature or proof is checked: a kind the directory
    /// does not have, a key or signature of the wrong size, an empty key, an oversize topic, a fee with no carrier, and
    /// trailing bytes.
    #[test]
    fn the_decode_refuses_malformed_objects_before_any_verify() {
        let fee = CreationFee {
            nullifier: [0u8; 32],
            leaf_commit: [0u8; 32],
            carrier: vec![1],
            membership_carrier: vec![1],
            membership_tip: vec![1],
            change_note: vec![0u8; 64],
            change_clue: vec![1],
        };
        let good = DirEntryTx { entry: entry(crate::directory::KIND_NAME, "alice", 0), fee, art: Vec::new() };
        // CALIBRATION: the well-formed object decodes, so each refusal below is its tamper's and not the fixture's
        assert_eq!(DirEntryTx::decode(&good.encode()).map(|t| t.entry.key), Some("alice".to_string()));
        let tampers: [(&str, fn(&mut DirEntryTx)); 8] = [
            ("an unknown kind", |t| t.entry.kind = 9),
            ("a short key", |t| {
                t.entry.pubkey.pop();
            }),
            ("a long signature", |t| t.entry.sig.push(0)),
            ("an empty key", |t| t.entry.key.clear()),
            ("an oversize topic", |t| t.entry.topic = "t".repeat(crate::directory::PROFILE_TOPIC_MAX + 1)),
            ("no carrier", |t| t.fee.carrier.clear()),
            ("no change clue", |t| t.fee.change_clue.clear()),
            ("a change note of no known size", |t| t.fee.change_note = vec![0u8; 65]),
        ];
        for (what, tamper) in tampers {
            let mut t = good.clone();
            tamper(&mut t);
            assert!(DirEntryTx::decode(&t.encode()).is_none(), "{what} was decoded");
        }
        let mut tail = good.encode();
        tail.push(0);
        assert!(DirEntryTx::decode(&tail).is_none(), "trailing bytes were decoded");
    }
}

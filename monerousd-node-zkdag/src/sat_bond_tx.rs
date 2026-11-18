// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ `Class::SatBond` — A CUSTODY BOND IN SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md §6; closes DB-391).
//!
//! The reserve's ≥ 2/3 tally is weighed in SAT bonded through this class. A validator spends a SAT note it owns: output 0
//! is LOCKED as the bond (never receivable; returned by `Class::Unbond` like the USDm bond's), output 1 is change. The
//! welded asset carrier (`usdm_decider::whir_rec_block::prove_asset_bond_validity_carrier_bytes`) proves, with the asset
//! tag and the weight PUBLIC: conservation in one asset, output 0 locks exactly `weight`, and the asset is SAT — so a bond
//! of USDm or of a worthless token can never seat custody weight. The validator's ML-DSA-65 signature over
//! [`sat_bond_msg`] binds the seat to the key that will sign custody statements.
//!
//! §9.6 door checklist (it parallels the USDm welded bond, DB-313, and the asset transfer, DB-223 Q7):
//! 1 PoW — rides a block whose grind the block door verified. 2 Proof — the welded carrier (asset tag + weight public) and
//! the note-membership carrier, both re-verified at the FOLD on every node. 3 Conservation — the carrier; output 0 is never
//! recorded as a note (`carried_note_payloads` names the change only), so a bond is not also a balance. 4 Replay — the
//! spent note's nullifier is this object's own nullifier, in the block's lane, refused by the spent SET; a second seat for
//! one validator is refused by the set (`AlreadyBonded`). 5 Bounded work — fixed fields, two carrier verifies. 6 Parity —
//! every check the USDm bond door runs (weld, membership cross-bind, lane nullifier, signed statement, lock) is here; the
//! one it lacks (the block aggregate) is replaced by per-object verification, which bonds' rarity affords.

use crate::hash::Hash32;
use crate::spend_frontier::Digest4;
use serde::{Deserialize, Serialize};

/// One custody bond in SAT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatBondTx {
    /// `[locked bond note (weight), change note]` — whole (`cover::PQ_NOTE_BYTES`) or in carriage form (`NOTE_REF_BYTES`).
    /// O1-FOOTPRINT-REVIEWED: two notes, protocol-constant widths; decode refuses any other.
    pub notes: [Vec<u8>; 2],
    pub nullifier: [u8; 32],
    pub leaf_commit: Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by `asset_tx::ASSET_SPEND_CARRIER_BYTES_MAX` — decode refuses wider.
    pub validity_carrier: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `asset_tx::ASSET_SPEND_CARRIER_BYTES_MAX` — decode refuses wider.
    pub membership_carrier: Vec<u8>,
    /// ⭐ §19 (2026-10-28, lane funds) — THE MEMBER LEG'S TUPLE (`member_transition::MEMBER_TUPLE_BYTES`): with it,
    /// `membership_carrier` is the member leg the bonding wallet's book (or the node's own, for its auto-bond) built
    /// against the chain's note frontier, judged by the one dispatcher every value door uses
    /// (`bond_membership_verdict`), and the record-naming fields below are zero — no `named_record` on the wire.
    /// Empty = the one-step form (a fixture's; this door retires it once the fixtures carry the leg).
    /// O1-FOOTPRINT-REVIEWED: one fixed-width tuple (128 B) or empty; `serde(default)` keeps every encoded bond decodable.
    #[serde(default)]
    pub member_tuple: Vec<u8>,
    pub named_record: u64,
    pub tip_prev: Digest4,
    pub tip_root: Digest4,
    pub tip_acc: Digest4,
    /// The custody weight, in SAT base units — exactly output 0's value, welded in the carrier.
    pub weight: u64,
    pub vid: [u8; 32],
    /// O1-FOOTPRINT-REVIEWED: bounded by `asset_tx::ASSET_MINT_AUTH_BYTES_MAX` — decode refuses wider.
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `asset_tx::ASSET_MINT_AUTH_BYTES_MAX` — decode refuses wider.
    pub sig: Vec<u8>,
    /// The change note's owner clue. O1-FOOTPRINT-REVIEWED: bounded by `peg_in_tx::OWNER_CLUE_MAX`.
    pub owner_clue: Vec<u8>,
    /// ⭐ SATOSHI §9 — the RE-BOND leg: `Some` ⇒ the carrier's SECOND input is this validator's CURRENTLY LOCKED note (named by
    /// its commitment, which the fold matches to `bond_locked[vid]`, and retired by its nullifier in the lane). `weight` is then
    /// the new total and REPLACES the seat's custody weight. `None` ⇒ a first seat, as before.
    pub rebond: Option<RebondLeg>,
}

/// ⭐ SATOSHI §9 — the locked input of a re-bond: its nullifier (retired by the spent SET, so the old locked note can never be
/// returned or re-bonded again) and its commitment (the fold's proof that it IS the validator's locked note — the carrier binds
/// both, docs §9.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebondLeg {
    pub nullifier_locked: [u8; 32],
    pub locked_cm: [u8; 32],
}

/// The ONE message the validator signs: which key seats, how much, which note it locks, which nullifier it retires.
#[must_use]
pub fn sat_bond_msg(vid: &[u8; 32], weight: u64, locked_cm: &[u8; 32], nullifier: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 8 + 64);
    m.extend_from_slice(b"MONEROUSD-SAT-BOND-v1");
    m.extend_from_slice(vid);
    m.extend_from_slice(&weight.to_le_bytes());
    m.extend_from_slice(locked_cm);
    m.extend_from_slice(nullifier);
    m
}

/// The ONE signed statement of a SAT bond — [`sat_bond_msg`], extended for a re-bond by the locked input it consumes. The bond
/// object and the wallet both build it here, so the bytes a validator signs and the bytes a node verifies cannot drift.
#[must_use]
pub fn sat_bond_statement(vid: &[u8; 32], weight: u64, locked_cm: &[u8; 32], nullifier: &[u8; 32], rebond: Option<&RebondLeg>) -> Vec<u8> {
    let mut m = sat_bond_msg(vid, weight, locked_cm, nullifier);
    if let Some(leg) = rebond {
        m.extend_from_slice(b"|MONEROUSD-SAT-REBOND-v1");
        m.extend_from_slice(&leg.nullifier_locked);
        m.extend_from_slice(&leg.locked_cm);
    }
    m
}
fn note_width_ok(n: &[u8]) -> bool {
    n.len() == crate::cover::PQ_NOTE_BYTES || n.len() == crate::chain_object::NOTE_REF_BYTES
}

impl SatBondTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }

    /// Refuses rather than guesses: widths and bounds, a zero weight, a key that is not the stated validator.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<SatBondTx> {
        let t: SatBondTx = crate::chain_object::decode_exact(bytes)?;
        let cap = crate::asset_tx::ASSET_SPEND_CARRIER_BYTES_MAX;
        let auth = crate::asset_tx::ASSET_MINT_AUTH_BYTES_MAX;
        if !t.notes.iter().all(|n| note_width_ok(n))
            || t.weight == 0
            || t.validity_carrier.is_empty()
            || t.validity_carrier.len() > cap
            || t.membership_carrier.is_empty()
            || t.membership_carrier.len() > cap
            || t.pubkey.is_empty()
            || t.pubkey.len() > auth
            || t.sig.is_empty()
            || t.sig.len() > auth
            || t.owner_clue.is_empty()
            || t.owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
            || crate::pqauth::pubkey_id(&t.pubkey) != t.vid
        {
            return None;
        }
        Some(t)
    }

    #[must_use]
    pub fn to_object(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::SatBond, &self.encode())
    }

    /// The two output commitments (locked, change), as the carrier states them.
    #[must_use]
    pub fn output_commitments(&self) -> Option<[Digest4; 2]> {
        let cm = |n: &[u8]| -> Option<Digest4> {
            let b: [u8; 32] = n.get(..32)?.try_into().ok()?;
            crate::spend_frontier::cm_bytes_to_root(&b)
        };
        Some([cm(&self.notes[0])?, cm(&self.notes[1])?])
    }

    #[must_use]
    pub fn locked_cm_bytes(&self) -> Option<[u8; 32]> {
        self.notes[0].get(..32)?.try_into().ok()
    }

    #[must_use]
    pub fn nullifier_digest(&self) -> Option<Digest4> {
        crate::spend_frontier::cm_bytes_to_root(&self.nullifier)
    }

    /// The ONE statement the validator signs: [`sat_bond_msg`], extended for a re-bond by the locked input it consumes (so a
    /// first-seat signature never authorises a re-bond and a re-bond's signature names exactly which locked note it replaces).
    #[must_use]
    pub fn statement(&self) -> Option<Vec<u8>> {
        Some(sat_bond_statement(&self.vid, self.weight, &self.locked_cm_bytes()?, &self.nullifier, self.rebond.as_ref()))
    }
    /// The validator's signature over [`Self::statement`], by the key that is `vid`.
    #[must_use]
    pub fn is_authorised(&self, v: &dyn crate::pqauth::PqVerifier) -> bool {
        let Some(m) = self.statement() else { return false };
        v.verify(&self.pubkey, &m, &self.sig)
    }
    /// Every nullifier this object retires: the fresh input's, and for a re-bond the locked input's too.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        let mut v = vec![self.nullifier];
        if let Some(leg) = &self.rebond {
            v.push(leg.nullifier_locked);
        }
        v
    }

    /// THE BLOB-ONLY HALF: the welded carrier opens (locked, change) in SAT, conserves value, and locks exactly `weight`.
    ///
    /// ⭐ Behind the verified-transition cache (`crate::verify_cache`, Bitcoin's script-execution cache): a carried bond is
    /// judged at its block's objects step on every lane justification and fold (`chain_object::admissible`) — MEASURED
    /// night/link29-sample2.txt, 494–603 samples of a fast journey re-running this one WHIR verify. The key binds every
    /// input the decider reads — the carrier, both stated output commitments, the nullifier, the leaf commitment, the
    /// weight, the SAT asset tag and, for a re-bond, the locked input's nullifier and commitment — so a hit is a prior TRUE
    /// for the identical statement, and a refusal is verified in full every time it is presented.
    #[must_use]
    pub fn weld_is_authorised(&self) -> bool {
        let (Some(cms), Some(nf)) = (self.output_commitments(), self.nullifier_digest()) else {
            return false;
        };
        let leg = match &self.rebond {
            None => None,
            Some(leg) => {
                let to = crate::spend_frontier::cm_bytes_to_root;
                let (Some(nf2), Some(cm2)) = (to(&leg.nullifier_locked), to(&leg.locked_cm)) else {
                    return false;
                };
                Some((nf2, cm2))
            }
        };
        let tag = crate::satoshi::asset_tag();
        let le = |d: &Digest4| -> [u8; 32] {
            let mut b = [0u8; 32];
            for (c, w) in b.chunks_exact_mut(8).zip(d) {
                c.copy_from_slice(&w.to_le_bytes());
            }
            b
        };
        let (leg_nf, leg_cm) = leg.map_or(([0u8; 32], [0u8; 32]), |(a, b)| (le(&a), le(&b)));
        let mut tag_le = [0u8; 24];
        for (c, w) in tag_le.chunks_exact_mut(8).zip(&tag) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        // ⭐ the verified-transition cache: the key binds every input the decider reads (shape word 0 = the re-bond arm)
        let key = crate::verify_cache::key(
            crate::verify_cache::Verifier::SatBondWeld,
            [u32::from(leg.is_some()), 0, 0, 0, 0, 0, 0, 0],
            &[
                self.validity_carrier.as_slice(),
                &le(&cms[0]),
                &le(&cms[1]),
                &le(&nf),
                &le(&self.leaf_commit),
                &self.weight.to_le_bytes(),
                &tag_le,
                &leg_nf,
                &leg_cm,
            ],
        );
        crate::verify_cache::verified(key, || match leg {
            None => usdm_decider::whir_rec_block::verify_asset_bond_validity_carrier_bytes(
                &self.validity_carrier,
                cms[0],
                cms[1],
                nf,
                self.leaf_commit,
                self.weight,
                tag,
            ),
            Some((nf2, cm2)) => usdm_decider::whir_rec_block::verify_asset_rebond_validity_carrier_bytes(
                &self.validity_carrier,
                cms[0],
                cms[1],
                nf,
                nf2,
                cm2,
                self.leaf_commit,
                self.weight,
                tag,
            ),
        })
    }
}

/// The fold's verdict on one bond object.
#[derive(Debug, PartialEq, Eq)]
pub enum SatBondApply {
    NotSatBond,
    /// Admitted by the block's OBJECTS step; its block's BOND step seats it ([`seat_sat_bond`]).
    Decided(SatSeat),
    Refused(&'static str),
}

/// A SAT bond its block's objects step admitted, carried to the same block's bond step, which seats it inside the bond
/// step's journal (`Node::bond_step_at_fold`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SatSeat {
    pub vid: [u8; 32],
    /// The custody weight: a first seat's weight, or a re-bond's new total.
    pub weight: u128,
    /// Output 0, the locked note (returned by `Class::Unbond`, burned by a slash).
    pub locked_note: Vec<u8>,
    pub rebond: bool,
}




/// The welded bond's witness over a note the bonder OWNS (a scanned SAT note: its `value_in` and its `owner` — DB-395: the
/// bonder's `(ask, nk)` and the note's seed), locking `weight` as output 0 and returning the rest as output 1 — the output
/// openings are those of the two freshly SEALED notes (`faucet::seal_asset_note` / the wallet's `seal_note_full_asset`, each
/// `P(spk_bonder, seed)`), so the locked note comes back spendable at unbond and the change is found by its owner like any
/// note. `lc_blind` is the membership cross-bind's per-object blind. `None` when `weight` exceeds the note.
#[must_use]
pub fn bond_witness(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    weight: u64,
    out0_opening: Digest4,
    out1_opening: Digest4,
    lc_blind: Digest4,
    asset: [u64; 3],
) -> Option<usdm_decider::whir_rec_block::AssetSpendValidityWitness> {
    let change = value_in.checked_sub(weight)?;
    if weight == 0 {
        return None;
    }
    Some(usdm_decider::whir_rec_block::AssetSpendValidityWitness {
        value_in,
        owner,
        value_out: value_in,
        fee: 0,
        lc_blind,
        out0_value: weight,
        out0_opening,
        out1_value: change,
        out1_opening,
        asset,
    })
}

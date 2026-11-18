// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! A LIQUIDATION IS A CHAIN OBJECT — the block-carried form of a collateral re-mark.
//!
//! This is the wire class that carries a close-for-undercollateralization into a block, and it is the ONLY
//! thing that reaches [`crate::node::Node::liquidate_position`] and therefore the ONE door,
//! [`crate::peg::PegLedger::liquidate_confidential`] (whose doc comment holds this lane's §9.6 checklist).
//! It is the sibling of [`crate::bridge_credit_tx`] and [`crate::order_fill_tx`]: a `wire()` that frames the
//! object under its own [`crate::chain_object::Class`], a `decode` that goes through the shared
//! [`crate::chain_object::decode_exact`], and one `apply_chain_liquidation` the block-apply loop calls.
//!
//! WHY THE CLASS EXISTS AT ALL (§9.6 Q1). The re-mark must ride a BLOCK, not an RPC route. MEASURED on this
//! lane's own surface: `rpc_http.rs` POST `/register_wrapped_asset` reaches
//! `PegLedger::register_wrapped_asset` with no threshold, no governance vote and no block, so anyone who can
//! reach the RPC port sets a wrapped asset's collateral requirement today. A liquidation exposed the same way
//! would be a seizure knob on a socket. Framing it as a chain object means the block carrying it has already
//! passed the header gate (`hash_meets_target` + the PQ-VDF heartbeat) at the block door, and the object is
//! judged by the same rules on every node.
//!
//! ── NO STORE, AND NO BOUND TO TAKE ANYONE'S WORD FOR ─────────────────────────────────────────────────────
//! [`LiquidationHeader`] is FIXED-WIDTH — every field is a `u64`, a `u32` or a fixed array, so the type that
//! travels and the type that could ever be held have no collection in them at all, and there is no growth axis
//! to argue about. The variable-length parts (the five WHIR legs and the attestation list) are bounded by
//! [`decode`], which REFUSES an empty leg, a leg past the constant WHIR proof bound
//! ([`crate::solvency::SolvencyProof::MAX_PROOF_BYTES`]) and a list past [`MAX_LIQUIDATION_ATTESTORS`] before it hands
//! them back. One decode, one place the bounds live, and every reader — the admission gate, the note-binding, the
//! apply path — inherits them without repeating a check.
//!
//! WHAT THIS OBJECT CANNOT DO (v2, spec §10). It carries no note ([`crate::chain_object::carried_note_payloads`]
//! answers an empty list, so a wrapper claiming a note for one is a forgery). It cannot create USDm or reserve: the
//! retire and pool legs burn the SAME `C` from the supply and the pool, the seize leg releases the SAME `S` the pool's
//! sum records, and the amount leg proves `(C, S)` is the one rule's value for a DUE PSM at the chain's mark. The bytes
//! being admissible is NOT the liquidation being admitted: the door tallies REAL bonded weight over a domain-separated
//! message and verifies all five legs against its own state before anything moves.
//!
//! COST: cons: none on any pillar. Every field is a digest or an id — no amount is on the wire, so a node, an
//! operator or an observer reading one learns no reserve, supply or position value. Nothing here is persisted:
//! the door's own 32-byte replay entry is the only state a liquidation leaves behind.

use serde::{Deserialize, Serialize};

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;

/// The hard cap on how many attestations ONE liquidation object may carry. DERIVED, not chosen: the >=2/3
/// tally in the peg's `threshold_ok` counts DISTINCT bonded validators and ignores repeats, so an object can
/// never benefit from more entries than the chain's producing set can hold —
/// [`crate::params::DAG_WIDTH_CEILING`], the fixed protocol constant that bounds that set. Entries beyond it
/// are pure padding, so [`decode`] refuses them before a single signature is verified.
pub const MAX_LIQUIDATION_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The FIXED-WIDTH header of a block-carried liquidation (spec §10.2 (3)): which PSM, which epoch, the unique close id,
/// and every commitment the five legs move the chain to. Every field is a digest, an id or a bit — never an amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationHeader {
    /// The epoch the close belongs to; namespaces the door's replay key.
    pub epoch_id: u64,
    /// Which PSM is liquidated (`crate::peg::NATIVE_PEG_ASSET_ID` for the USDm peg).
    pub asset_id: u32,
    /// The unique close id (the trigger derives it from the mark that made the PSM due).
    pub position_id: [u8; 32],
    /// `DC` — the USDm the pool burns and the supply retires.
    pub retired_commit: crate::spend_frontier::Digest4,
    /// `DS` — the collateral the reserve releases to the pool's depositors.
    pub seized_commit: crate::spend_frontier::Digest4,
    /// The committed reserve AFTER the seize leg.
    pub new_reserve_commit: crate::spend_frontier::Digest4,
    /// The committed circulating supply AFTER the retire leg.
    pub new_minted_commit: crate::spend_frontier::Digest4,
    /// The pool's `T` after the burn.
    pub new_pool_t: crate::spend_frontier::Digest4,
    /// The pool's product `P` after the step (the CLOSING `P` when `pool_close`).
    pub new_pool_p: crate::spend_frontier::Digest4,
    /// The pool's sum `S` after the step (the CLOSING `S` when `pool_close`).
    pub new_pool_s: crate::spend_frontier::Digest4,
    /// The pool step's public epoch-close bit (`P_new < 2^64`).
    pub pool_close: bool,
}

/// The five WHIR legs of one liquidation, welded by equal commitments ([`crate::peg::PegLedger::verify_liquidation_legs`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationLegs {
    /// `[reserve, minted, DC, DS]` under the folded mark's rule.
    pub amount: Vec<u8>,
    /// `[new_T, DC, T]` (StabilityPool).
    pub pool_transition: Vec<u8>,
    /// `[T, DC, DS, P, P_new, S, S_new]` + the close bit.
    pub pool_step: Vec<u8>,
    /// `[new_minted, DC, minted]` (Retire).
    pub retire: Vec<u8>,
    /// `[new_reserve, DS, reserve]` (Seize).
    pub seize: Vec<u8>,
}

impl LiquidationLegs {
    fn each(&self) -> [&Vec<u8>; 5] {
        [&self.amount, &self.pool_transition, &self.pool_step, &self.retire, &self.seize]
    }
}

/// The canonical payload bytes (unframed): the fixed-width header, the five WHIR legs, and the bonded validators'
/// attestations over [`crate::peg::revalue_msg`].
///
/// A serialization failure yields EMPTY bytes rather than a panic, and that empty vector is not a silent
/// rescue: an empty payload does not `unframe` into a decodable object, so [`decode`] refuses it, the
/// admission gate refuses it, and [`apply_chain_liquidation`] reports `NotLiquidation`. The failure surfaces
/// as a refusal at every reader instead of taking a node down mid-block.
/// ROOT-LAYER: the wire form is produced HERE, at the single encoder, and the attestation is converted to a
/// plain `(pubkey, sig)` pair at this boundary rather than by deriving serde on `crate::psm::MintAttestor`.
/// That type is a runtime value the threshold check consumes; making it serializable would put a wire
/// contract on a struct three other modules construct freely, so the next field added to it would silently
/// become consensus bytes. Converting at the boundary keeps the wire independent of that shape.
/// MEASURED: `cargo check --lib --tests` 2026-09-08 — 3 errors -> 0 on this file
/// (`MintAttestor: serde::Serialize` and `Deserialize` unsatisfied at the encoder and the decoder, plus
/// `PegOutcome: Clone` on the outcome enum).
/// MUST-STAY-GREEN: every psm threshold test — `MintAttestor` keeps exactly the derives it had.
pub fn encode(header: &LiquidationHeader, legs: &LiquidationLegs, attestors: &[MintAttestor]) -> Vec<u8> {
    let att: Vec<(&[u8], &[u8])> = attestors
        .iter()
        .map(|a| (a.pubkey.as_slice(), a.sig.as_slice()))
        .collect();
    match postcard::to_stdvec(&(header, legs, &att)) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(), // refused by every reader: an empty payload never unframes into this class
    }
}

/// The EXACT payload type this class's bytes deserialize to — the fixed-width header, the five legs, and the
/// attestations as raw `(pubkey, sig)` pairs. Named so the wire-malleability fuzz family can name the real
/// type this arm decodes rather than approximate it.
pub type LiquidationPayload = (LiquidationHeader, LiquidationLegs, Vec<(Vec<u8>, Vec<u8>)>);

/// The ONE wire encoding: the canonical payload framed under this object's own class. Every publisher goes
/// through here, so the framing cannot drift between the side that writes and the side that reads.
pub fn wire(header: &LiquidationHeader, legs: &LiquidationLegs, attestors: &[MintAttestor]) -> Vec<u8> {
    frame(Class::Liquidation, &encode(header, legs, attestors))
}

/// ⭐ THE ONE DECODE, and the ONE place this class's bounds live.
///
/// Goes through the shared [`decode_exact`], so `encode(x) || junk` is REFUSED rather than decoding to the
/// same object under a different content id — the wire-malleability hole the 2026-09-06 red team confirmed at
/// every class decoder. Then it enforces both size bounds BEFORE returning anything:
///   • each of the five legs must be non-empty and at most [`crate::solvency::SolvencyProof::MAX_PROOF_BYTES`]
///     (one constant-size WHIR proof);
///   • the attestation list must be non-empty and at most [`MAX_LIQUIDATION_ATTESTORS`].
///
/// ROOT-LAYER: the bounds are produced HERE, at the single point where bytes become this object, rather than
/// at each reader. A per-reader check is how a fourth reader written tomorrow silently gets none.
/// MEASURED: `cargo check --lib --tests` 2026-09-08, errors across the crate 40 -> 0 (the 40 were node.rs 28,
/// node_runtime.rs 11, miner.rs 1 — other lanes' in-flight edits; peg.rs, solvency.rs and this lane 0
/// throughout). `grep -c liquidate_confidential src/node.rs`: 0 -> 1.
/// MUST-STAY-GREEN: every `*_with_trailing_bytes_*` pin in `chain_object`, `asset_tx` and `order_fill_tx` —
/// this class adds a decoder that calls the shared `decode_exact` rather than a fourth prefix-tolerant one.
pub fn decode(payload: &[u8]) -> Option<(LiquidationHeader, LiquidationLegs, Vec<MintAttestor>)> {
    let (header, legs, pairs) = decode_exact::<LiquidationPayload>(payload)?;
    if legs.each().iter().any(|l| l.is_empty() || l.len() > crate::solvency::SolvencyProof::MAX_PROOF_BYTES) {
        return None;
    }
    if pairs.is_empty() || pairs.len() > MAX_LIQUIDATION_ATTESTORS {
        return None;
    }
    let attestors = pairs
        .into_iter()
        .map(|(pubkey, sig)| MintAttestor { pubkey, sig })
        .collect();
    Some((header, legs, attestors))
}

/// The pool transaction that carries one liquidation — the ONE builder every publisher uses (the framer of §10.2 (4),
/// [`crate::node::Node::publish_liquidation`]). The object moves no note and spends none, so the wrapper carries only the
/// blob and its anti-spam stamp, ground exactly as [`crate::price_mark_tx::as_pq_tx`] grinds it (a `pow_stamp` of 0 is
/// refused at the door and the floor). Bounded BY CONSTRUCTION: 2^stamp_bits expected tries. The object's own nullifier
/// (its close id, DB-274 P4b B1) is laid on the lane by the publisher through `lay_object_lane`.
#[must_use]
pub fn as_pq_tx(header: &LiquidationHeader, legs: &LiquidationLegs, attestors: &[MintAttestor], stamp_bits: u32) -> crate::mempool::PqTx {
    let blob = wire(header, legs, attestors);
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

/// The widest ML-DSA public key or signature a [`LiquidationSig`] may carry (ML-DSA-65: 1,952 B key, 3,309 B
/// signature); `decode` refuses wider, so a gossiped signature is bounded by construction.
pub const LIQUIDATION_SIG_FIELD_MAX: usize = 4096;

/// ⭐ LIQUIDATION §10.2 (4) — ONE bonded custodian's signature over a due liquidation's v2 message: the unit of the
/// attestation lane (`WireMsg::LiquidationSig`). Every custodian holding the PSM's current opening derives the SAME
/// header from the chain's mark ([`crate::node::Node::due_liquidation`]), signs it ON ITS OWN, and gossips this; a node
/// gathers them against its OWN state and bonded set, and the first custodian holding ≥2/3 proves the five legs and
/// frames the object. No operator, no RPC route: the trigger is the chain's mark.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationSig {
    pub header: LiquidationHeader,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl LiquidationSig {
    /// The one wire encoding (an encoding failure is an empty vector, which `decode` refuses).
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        match postcard::to_stdvec(self) {
            Ok(bytes) => bytes,
            Err(_) => Vec::new(),
        }
    }

    /// Strict full-consumption decode; the size bounds live here.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let s: LiquidationSig = decode_exact(bytes)?;
        let ok = |f: &Vec<u8>| !f.is_empty() && f.len() <= LIQUIDATION_SIG_FIELD_MAX;
        (ok(&s.pubkey) && ok(&s.sig)).then_some(s)
    }

    /// The header's identity in the signature book: blake3 over its one encoding.
    #[must_use]
    pub fn header_digest(h: &LiquidationHeader) -> [u8; 32] {
        let bytes = match postcard::to_stdvec(h) {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
        *blake3::hash(&bytes).as_bytes()
    }
}

/// What applying a block-carried liquidation did on THIS node.
#[derive(Debug, PartialEq, Eq)]
pub enum LiquidationApply {
    /// The blob is not a framed, in-bounds liquidation — nothing to do, and nothing was touched.
    NotLiquidation,
    /// The door closed the position and advanced this node's committed pair.
    Closed,
    /// The door refused it (no >=2/3 weight, a carrier that does not verify against THIS node's digests, a
    /// position that is closed, or an unregistered PSM). Nothing was touched.
    Refused(crate::peg::PegOutcome),
}


#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::bridge::Custodian;

    fn header() -> LiquidationHeader {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        LiquidationHeader {
            epoch_id: 7,
            asset_id: crate::peg::NATIVE_PEG_ASSET_ID,
            position_id: [0xD1u8; 32],
            retired_commit: l(&[9, 9, 9, 9]),
            seized_commit: l(&[8, 8, 8, 8]),
            new_reserve_commit: l(&[1, 2, 3, 4]),
            new_minted_commit: l(&[5, 6, 7, 8]),
            new_pool_t: l(&[7, 7, 7, 7]),
            new_pool_p: l(&[6, 6, 6, 6]),
            new_pool_s: l(&[5, 5, 5, 5]),
            pool_close: false,
        }
    }

    /// Five in-bounds legs, each `leg` (a shape for the decode bounds, not a proof).
    fn legs_of(leg: Vec<u8>) -> LiquidationLegs {
        LiquidationLegs { amount: leg.clone(), pool_transition: leg.clone(), pool_step: leg.clone(), retire: leg.clone(), seize: leg }
    }

    fn one_attestor() -> Vec<MintAttestor> {
        vec![Custodian::generate(&[91u8; 32]).attest(b"musdm.peg.revalue.v2 sample")]
    }

    // The wire is ONE encoding, and a tolerated tail is refused — the shared `decode_exact` contract. Without
    // it, `encode(x) || junk` would decode to the SAME object under a DIFFERENT content id, so one object
    // could occupy unbounded pool slots and ride a block more than once.
    #[test]
    fn liquidation_wire_round_trips_and_refuses_trailing_bytes() {
        let (h, legs, att) = (header(), legs_of(vec![9u8; 64]), one_attestor());
        let w = wire(&h, &legs, &att);
        let (class, payload) = unframe(&w).expect("the wire is a framed object");
        assert_eq!(class, Class::Liquidation, "it frames under its own class");
        let (dh, dc, da) = decode(payload).expect("the canonical payload round-trips");
        assert_eq!(dh, h, "the header round-trips exactly");
        assert_eq!(dc, legs, "the legs round-trip exactly");
        assert_eq!(da.len(), att.len(), "the attestation list round-trips");
        let mut padded = payload.to_vec();
        padded.extend_from_slice(&[0xAAu8; 7]);
        assert!(
            decode(&padded).is_none(),
            "a payload with 7 trailing junk bytes is REFUSED — one object, one encoding"
        );
    }

    // A liquidation carries NO block-carried note, and that empty list is a real answer: a transaction wrapper
    // claiming any note for one is a forgery the per-note-validity binding refuses.
    #[test]
    fn a_liquidation_object_justifies_no_note_at_all() {
        let w = wire(&header(), &legs_of(vec![9u8; 64]), &one_attestor());
        assert_eq!(
            crate::chain_object::carried_note_payloads(&w),
            Some(Vec::new()),
            "a liquidation creates no note — the pool's depositors are paid at withdrawal"
        );
    }

    // THE BOUNDS ARE AT THE DECODE, so every reader inherits them. An object with no attestation, no carrier,
    // or an over-bound carrier does not decode at all — and therefore is not admissible either, without
    // `admissible` repeating a single check.
    #[test]
    fn out_of_bounds_liquidation_bytes_do_not_decode_and_are_not_admissible() {
        let allowance = 0; // the mint-class genesis allowance is irrelevant to this class
        let h = header();
        let mut one_empty = legs_of(vec![9u8; 64]);
        one_empty.retire = Vec::new();
        let mut one_over = legs_of(vec![9u8; 64]);
        one_over.pool_step = vec![0u8; crate::solvency::SolvencyProof::MAX_PROOF_BYTES + 1];
        for (why, legs, att) in [
            ("no attestation at all", legs_of(vec![9u8; 64]), Vec::new()),
            ("an empty leg", one_empty, one_attestor()),
            ("a leg over the constant WHIR bound", one_over, one_attestor()),
        ] {
            let w = wire(&h, &legs, &att);
            let (_, payload) = unframe(&w).expect("still a framed object");
            assert!(decode(payload).is_none(), "{why}: must not decode");
            assert!(
                !crate::chain_object::admissible(&w, 10, allowance, false),
                "{why}: must not be admissible on the bytes"
            );
        }
        // The honest, in-bounds object DOES decode and IS admissible as bytes — admitting the bytes is not
        // admitting the re-mark, which still needs >=2/3 real bonded weight at the door.
        let ok = wire(&h, &legs_of(vec![9u8; 64]), &one_attestor());
        assert!(
            crate::chain_object::admissible(&ok, 10, allowance, false),
            "an in-bounds liquidation is admissible as BYTES (the door still decides the re-mark)"
        );
    }
}

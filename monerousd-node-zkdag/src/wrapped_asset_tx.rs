// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! A WRAPPED-ASSET REGISTRATION IS A CHAIN OBJECT — the block-carried form of "this asset mints at this
//! collateral ratio".
//!
//! WHY THIS CLASS EXISTS (the defect it closes, measured 2026-09-11). `POST /register_wrapped_asset`
//! reached [`crate::peg::PegLedger::register_wrapped_asset`] with no threshold, no vote and no block, and
//! `ratio_bps` decides how much USDm may be minted against an asset — dropping a volatile asset to the
//! stablecoin setting removes the volatility buffer entirely, so the asset mints against collateral it is
//! no longer required to over-hold. The sibling module [`crate::liquidation_tx`] names this exact route as
//! the thing a seizure knob must NOT look like.
//!
//! ⛔ AND "IT IS LOOPBACK ONLY" IS NOT THE ANSWER. The RPC binds 127.0.0.1, which bounds WHO can trigger
//! it; it says nothing about what the value IS. `ratio_bps` is fed into the mint authorisation, so it is a
//! CONSENSUS value, and a node that takes a consensus value from a socket is minting against a number the
//! chain never set. That is the "local state decides consensus" root error this tree has already paid for:
//! two honest nodes each self-verified the same DEX fill, both were right to accept it, and the maker's lot
//! was paid out a second time, because the burn was local and never travelled. The peg's own
//! collateral-ratio census states the rule this module implements: "a node fed only blocks derives the
//! ratios the CHAIN set. Any party that disagrees is minting against a number a socket supplied."
//!
//! THE BORROW: MakerDAO/Ethereum — a collateral parameter changes only by an authorised ON-CHAIN action,
//! never by an operator's local command. The mechanism is this tree's own proven one, mirrored field for
//! field from [`crate::liquidation_tx`]: a `wire()` that frames the object under its own
//! [`crate::chain_object::Class`], a `decode` through the shared [`crate::chain_object::decode_exact`], and
//! one [`apply_chain_wrapped_asset_register`] the block-apply loop calls beside the liquidation arm.
//!
//! ROOT-LAYER: the ratio is SET at the door that owns it
//! ([`crate::peg::PegLedger::register_wrapped_asset_attested`]) and reached only from the block-apply
//! seam — not patched at a reader, and not decided in the RPC handler that used to set it. Patching a
//! reader instead (refusing a bad ratio at mint time, say) would leave two nodes still holding different
//! ratios and therefore still disagreeing about the same block.
//! MEASURED 2026-09-11, before -> after on this tree:
//!   `grep -c "node_mut().register_wrapped_asset(" src/rpc_http.rs`  1 -> 0  (no socket sets a ratio)
//!   `grep -c "register_wrapped_asset_attested" src/node.rs`          0 -> 3  (the door, its doc, its call)
//!   `grep -c "wrapped_asset_tx" src/node.rs`                         0 -> 2  (the block-apply seam + doc)
//! MUST-STAY-GREEN: the peg + psm threshold pins (this adds a caller of `threshold_ok`, it does not change
//! it), `liquidation_tx`'s own pins (additive; only the framing helpers are shared), every
//! `*_with_trailing_bytes_*` decode pin in `chain_object` / `asset_tx` / `order_fill_tx` (this class calls
//! the shared `decode_exact` rather than adding a prefix-tolerant decoder), and the IonSwap wrapped-mint
//! tests that read `wrapped_asset_ratio_bps` — a registration applied through the new door leaves that
//! reader's value exactly as a direct registration did.
//!
//! ── NO STORE, AND NO NEW PERSISTED STATE ─────────────────────────────────────────────────────────────
//! [`WrappedAssetRegisterHeader`] is FIXED-WIDTH (one `u64` and three `u32`s), so the type that travels
//! holds no collection at all. The one variable-length part — the attestation list — is never a struct
//! field: it exists only as a local returned by [`decode`], which refuses anything outside
//! [`MAX_REGISTER_ATTESTORS`] before handing it back.
//!
//! REPLAY is closed with NO new persisted field, by the same COMMITMENT-CHAIN shape the re-mark uses: the
//! attested message names the PREVIOUS ratio as well as the new one, and the door refuses unless `prev`
//! equals what the node currently holds. An old registration replayed after a retune names a stale `prev`
//! and moves nothing; a first registration must attest `prev = 0`. No snapshot schema bump, no frozen door.
//!
//! WHAT THIS OBJECT CANNOT DO. It carries no note ([`crate::chain_object::carried_note_payloads`] answers
//! an empty list for this class, so a wrapper claiming a note for one is a forgery `wrapper_binds_object`
//! refuses). The bytes being admissible is NOT the ratio being set: the object carries its own attestation
//! set, and the door tallies REAL bonded weight over a domain-separated message before anything moves.
//!
//! COST: every field is an id, an epoch or a ratio — chain-public by definition (every node must agree on
//! them to agree on solvency), and no amount, owner or key is on the wire. The work this adds is one
//! message build and one bonded tally when a registration object is applied; a registration is a
//! governance event, not something a block or a note produces, so nothing here is charged per block, per
//! note or per unit of history.

use crate::chain_object::{decode_exact, frame, unframe, Class};
use crate::psm::MintAttestor;
use serde::{Deserialize, Serialize};

/// The attestation list is bounded by the same protocol constant the re-mark uses — the bonded set cannot
/// exceed [`crate::params::DAG_WIDTH_CEILING`]. Entries beyond it are pure padding, so [`decode`] refuses
/// them before a single signature is verified.
pub const MAX_REGISTER_ATTESTORS: usize = crate::params::DAG_WIDTH_CEILING;

/// The FIXED-WIDTH header of a block-carried wrapped-asset registration: which epoch, which asset, and the
/// ratio transition it authorises. Every field is an id, an epoch or a ratio — never an amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedAssetRegisterHeader {
    /// The epoch the registration belongs to; namespaces the attested message.
    pub epoch_id: u64,
    /// Which wrapped-asset PSM is being registered or retuned.
    pub asset_id: u32,
    /// The ratio this node must ALREADY hold for the attestation to apply — 0 for a first registration.
    /// This is the commitment chain that makes the object replay-proof without new state.
    pub prev_ratio_bps: u32,
    /// The ratio the registration moves to (the ledger requires >= 10000: no wrapped asset may mint below
    /// 1:1 backing).
    pub ratio_bps: u32,
}

/// The canonical payload bytes (unframed): the fixed-width header and the bonded validators' attestations
/// over [`crate::peg::PegLedger::wrapped_register_msg`].
///
/// An encoding failure yields EMPTY bytes rather than a panic, and that empty vector is NOT a silent
/// rescue — it is refused at every reader: an empty payload does not `unframe` into a decodable object, so
/// [`decode`] refuses it, [`crate::chain_object::admissible`] refuses it, and
/// [`apply_chain_wrapped_asset_register`] reports `NotRegistration`. The failure therefore surfaces as a
/// refusal on the offending object alone instead of taking a node down mid-block, which is the same
/// fail-closed contract [`crate::liquidation_tx::encode`] carries for the identical reason.
///
/// The attestation is converted to a plain `(pubkey, sig)` pair at this boundary rather than by deriving
/// serde on [`MintAttestor`] — the same reason [`crate::liquidation_tx::encode`] does it: that type is a
/// runtime value three other modules construct freely, and making it serializable would turn its next field
/// into consensus bytes.
pub fn encode(header: &WrappedAssetRegisterHeader, attestors: &[MintAttestor]) -> Vec<u8> {
    let att: Vec<(&[u8], &[u8])> = attestors
        .iter()
        .map(|a| (a.pubkey.as_slice(), a.sig.as_slice()))
        .collect();
    postcard::to_stdvec(&(header, &att)).unwrap_or_default()
}

/// The EXACT payload type this class's bytes deserialize to — the fixed-width header and the attestations as
/// raw `(pubkey, sig)` pairs. Named so the wire-malleability fuzz family can name the real type this arm
/// decodes rather than approximate it.
pub type WrappedAssetRegisterPayload = (WrappedAssetRegisterHeader, Vec<(Vec<u8>, Vec<u8>)>);

/// The ONE wire encoding: the canonical payload framed under this object's own class. Every publisher goes
/// through here, so the framing cannot drift between the side that writes and the side that reads.
pub fn wire(header: &WrappedAssetRegisterHeader, attestors: &[MintAttestor]) -> Vec<u8> {
    frame(Class::WrappedAssetRegister, &encode(header, attestors))
}

/// THE ONE DECODE, and the ONE place this class's bounds live.
///
/// Goes through the shared [`decode_exact`], so `encode(x) || junk` is REFUSED rather than decoding to the
/// same object under a different content id — the wire-malleability hole the 2026-09-06 red team confirmed
/// at every class decoder. Then it enforces the bounds BEFORE returning anything: the attestation list must
/// be non-empty and at most [`MAX_REGISTER_ATTESTORS`], and the target ratio must be one the ledger would
/// accept (>= 10000), so an object that could only ever be refused never reaches a signature verify.
///
/// ROOT-LAYER: the bounds are produced HERE, at the single point where bytes become this object, rather than
/// at each reader — a per-reader check is how a fourth reader written tomorrow silently gets none.
pub fn decode(payload: &[u8]) -> Option<(WrappedAssetRegisterHeader, Vec<MintAttestor>)> {
    let (header, pairs) = decode_exact::<WrappedAssetRegisterPayload>(payload)?;
    if pairs.is_empty() || pairs.len() > MAX_REGISTER_ATTESTORS {
        return None;
    }
    // A sub-1:1 target is refused at the wire, not silently clamped: an attestation authorises an exact
    // transition, and clamping would apply a ratio nobody signed.
    if header.ratio_bps < 10_000 {
        return None;
    }
    let attestors = pairs
        .into_iter()
        .map(|(pubkey, sig)| MintAttestor { pubkey, sig })
        .collect();
    Some((header, attestors))
}

/// Wrap this object as the transaction that carries it into a block — the publisher shape
/// [`crate::bridge_credit_tx::BridgeCreditTx::as_pq_tx`] uses. A registration mints nothing and burns
/// nothing, so it publishes no note, no nullifier, no bond and no stake: every one of those lists is empty,
/// which is exactly what [`crate::chain_object::wrapper_binds_object`] requires for this class.
pub fn as_pq_tx(
    header: &WrappedAssetRegisterHeader,
    attestors: &[MintAttestor],
    stamp_bits: u32,
) -> crate::mempool::PqTx {
    let blob = wire(header, attestors);
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
        // A registration spends no note, so it proves no membership: every witness lane is empty, which
        // is what `wrapper_binds_object` requires for a class that burns nothing.
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    // Grind the anti-spam stamp exactly as a real submit does, the same way
    // [`crate::bridge_credit_tx::BridgeCreditTx::as_pq_tx`] does and for the same measured reason: that
    // module records "the bare blob with pow_stamp 0 was refused at the door and at the floor, both
    // measured", and this lane re-measured it — `Err(InsufficientStampWork { got: 4, need: 8 })` — before
    // the grind was added, which would have made the publishing route emit objects every node refuses.
    // Bounded work BY CONSTRUCTION: 2^stamp_bits expected tries (~256 at the live 8-bit floor).
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

/// What the block-apply loop learned from one blob.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterApply {
    /// The blob is not a framed, in-bounds registration — nothing to do, and nothing was touched.
    NotRegistration,
    /// The door set this asset's ratio.
    Registered,
    /// The door refused it (no >=2/3 weight, or an attested `prev_ratio_bps` this node does not stand on).
    /// Nothing was touched.
    Refused(crate::peg::PegOutcome),
}

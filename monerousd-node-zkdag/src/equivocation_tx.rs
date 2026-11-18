// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ DB-266 — `Class::Equivocation`: A SLASH IS A CHAIN OBJECT, BECAUSE IT BURNS A BOND.
//!
//! ## What this replaces, and why it was a divergence
//! Both finality-vote doors slashed LOCALLY on `VoteRecord::Equivocation` (`validators.slash(&voter)`), and the mesh
//! door then refused to re-gossip the conflicting vote. A node learnt of an equivocation only if the second vote
//! reached it directly, so an equivocator that sent its second vote to a SUBSET of nodes was slashed on exactly that
//! subset. The validator set, and every ≥2/3 denominator measured against it (finality, the bond-weighted custody
//! tally, wrapped-asset registration, price marks), then differed between honest nodes. It is the §AS shape (a
//! value-moving transition applied as a local mutation, not a chain object the block carries), for slashing.
//!
//! ## The borrowed shape
//! Ethereum's `AttesterSlashing` / `ProposerSlashing` are OPERATIONS INCLUDED IN BLOCKS. The evidence (two conflicting
//! signed messages) is verified by every node at block processing, and the slash happens there. Seeing the evidence
//! locally only makes a node PUBLISH it.
//!
//! ## The object
//! Two finality votes by ONE key at ONE height naming DIFFERENT blocks.
//! - Every node verifies both ML-DSA-65 signatures over `pqauth::finality_vote_msg(block, height)` under the object's
//!   one pubkey, and RECOMPUTES the voter id as `H(pubkey)`. It never takes a claimed id.
//! - The pair is canonical (the lower block id first), so one equivocation has one encoding and one content id; a
//!   reordered copy is refused at decode.
//! - The blocks need not be held. A signature over two different (block, height) pairs is an equivocation whether or
//!   not this node holds either block, and requiring them would let an equivocator vote for a block it never releases.
//!
//! Per-object work: one strict decode and two signature verifies. No term in height, block count, note count or peers.
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;

/// The widest honest evidence object: one ML-DSA-65 public key (1,952 B), two signatures (3,309 B each), two block
/// ids, the height and postcard framing — about 8.7 KB. A payload wider than 16 KiB is refused before it is parsed.
pub const EQUIVOCATION_WIRE_MAX: usize = 16 * 1024;

/// The vote doors' publication queue holds at most this many conflicting certs between two runtime ticks; past it
/// the oldest is dropped. A dropped cert costs one publication, never a wrong slash: any node that saw the same
/// pair publishes the same canonical object, and a block needs it only once.
pub const EQUIVOCATION_QUEUE_MAX: usize = 64;

/// The payload: `(pubkey, height, (block_a, sig_a), (block_b, sig_b))` with `block_a < block_b`.
pub type EquivocationPayload = (Vec<u8>, u64, ([u8; 32], Vec<u8>), ([u8; 32], Vec<u8>));

/// The canonical encoding of the evidence two certs make, or `None` when they are not an equivocation (two keys, two
/// heights, or one block).
#[must_use]
pub fn encode(a: &crate::validator::VoteCert, b: &crate::validator::VoteCert) -> Option<Vec<u8>> {
    if a.pubkey != b.pubkey || a.height != b.height || a.block == b.block {
        return None;
    }
    let (lo, hi) = if a.block.0 < b.block.0 { (a, b) } else { (b, a) };
    let payload: EquivocationPayload =
        (lo.pubkey.clone(), lo.height, (lo.block.0, lo.sig.clone()), (hi.block.0, hi.sig.clone()));
    postcard::to_allocvec(&payload).ok()
}

/// Frame the evidence as a `Class::Equivocation` object — the one publication path.
#[must_use]
pub fn wire(a: &crate::validator::VoteCert, b: &crate::validator::VoteCert) -> Option<Vec<u8>> {
    let framed = crate::chain_object::frame(Class::Equivocation, &encode(a, b)?);
    if framed.len() > EQUIVOCATION_WIRE_MAX {
        return None; // wider than any honest evidence — never framed
    }
    Some(framed)
}

/// Strict decode: one encoding (`decode_exact`), non-empty key and signatures, and the canonical block order.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<EquivocationPayload> {
    if payload.len() > EQUIVOCATION_WIRE_MAX {
        return None; // wider than any honest evidence — refused before it is parsed
    }
    let (pubkey, height, a, b) = decode_exact::<EquivocationPayload>(payload)?;
    if pubkey.is_empty() || a.1.is_empty() || b.1.is_empty() {
        return None;
    }
    if a.0 >= b.0 {
        return None; // not canonical, or one block twice: not an equivocation, and not its one encoding
    }
    Some((pubkey, height, a, b))
}

/// ⭐ SELF-VERIFYING FROM THE OBJECT ALONE: `Some(voter id)` iff both signatures are the key-holder's over two
/// DIFFERENT blocks at ONE height. The id is `H(pubkey)`, recomputed here.
#[must_use]
pub fn proves_equivocation(payload: &[u8], v: &dyn PqVerifier) -> Option<[u8; 32]> {
    let (pubkey, height, (block_a, sig_a), (block_b, sig_b)) = decode(payload)?;
    let signed = |block: [u8; 32], sig: &[u8]| {
        v.verify(&pubkey, &crate::pqauth::finality_vote_msg(&crate::hash::Hash32(block), height), sig)
    };
    if !signed(block_a, &sig_a) || !signed(block_b, &sig_b) {
        return None;
    }
    Some(crate::pqauth::pubkey_id(&pubkey))
}

/// What applying an evidence object did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EquivocationApply {
    /// Not an equivocation object — left entirely alone.
    NotEquivocation,
    /// The voter was bonded here and is now slashed: its bond burned, its id barred.
    Slashed(u128),
    /// Refused before anything moved, with the reason a node can act on.
    Refused(&'static str),
}


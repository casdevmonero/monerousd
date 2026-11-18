// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ `Class::MembershipBond` — A VALIDATOR SEAT THAT RIDES THE CHAIN, FREE WHILE THERE IS NOTHING TO SECURE.
//!
//! ## What this replaces, and the measurement that forced it
//! A validator used to be seated by `MONEROUSD_VALIDATOR_BOND` (or a pinned `MONEROUSD_CHARTER_QUORUM`)
//! calling `Node::admit_validator` DIRECTLY at startup — a local write that never travelled. MEASURED
//! 2026-09-17 on two REAL peered `usdmd-node` processes: each answered `{"validators":1}` (itself and
//! nobody else), node0 minted a BTC deposit, node0 correctly refused its own replay, and **node1 minted the
//! SAME deposit again** — node0's attestation failed threshold against node1's disjoint set, so
//! `apply_chain_peg_in` returned before the replay-set insert. One deposit, N nodes, N mints (§CW).
//!
//! §AS had already closed the UNBOND (a local release became `Class::Unbond`); the BOND itself was never
//! closed. This is that closure: the seat is a chain object, carried in `Block::bond_set` beside `Unbond`,
//! applied by every grafting node from the same bytes.
//!
//! ## No founding keys — the chain records who bonded first
//! Owner, 2026-09-17: *"the founding genesis quorum should simply be the first two nodes on the chain … i
//! dont even think founding keys are necessary."* Correct: there is no genesis constant and no env var.
//! Every node grafts the same blocks in the same order, so every node derives the same first members.
//!
//! ## Free exactly when the adaptive rule says the required bond is zero
//! Owner: *"membership bonding should be free whenever the required bond equals zero (i.e., reserve is
//! zero)."* The backstop rule is `bond >= 2 x reserve`; at zero reserve the required bond is zero, so a
//! collateral-free seat is the rule evaluated at its zero point, not a privilege. The reserve is a HIDING
//! commitment, but ZERO is a known constant (`solvency_commit(0, GENESIS_PEG_RESERVE_BLIND)`), so
//! `reserve == 0` is decidable on every node as `reserve_commit == genesis zero commit`. P6 proves a full
//! peg-out returns to exactly that constant, so the free window reopens when there is nothing to secure.
//!
//! ⛔ THE LAUNCH ASSUMPTION, STATED: the free window is open to anyone until the first applied deposit,
//! and a seat taken then is kept. The operators' nodes must be the first to bond — they are the only ones
//! online at genesis. That is the standard PoS genesis assumption; it is operational, not cryptographic.
//!
//! ## Membership weight is not backing
//! Founders post NO collateral (owner: *"the collateral naturally comes in from the community"*). The
//! weight admitted here exists so `peg::threshold_ok` can reach a verdict — it skips any attestor whose
//! `bond_of == 0` BEFORE checking the signature, so a literally-zero member could never attest. Equal
//! weight per member makes the >=2/3 rule count MEMBERS. The depositor's BTC is the reserve and backs
//! itself in threshold custody; the bond is anti-theft weight, never a cap on a user's money.

use crate::chain_object::decode_exact;
use serde::{Deserialize, Serialize};

/// The exact width of a compressed foreign-chain custody point. A protocol constant of the bridge's
/// external key encoding; `decode` refuses any other length, so a header is fixed-width by construction.
pub const CUSTODY_POINT_BYTES: usize = 33;
/// The exact width of an ML-KEM-768 encapsulation key (FIPS 203). `decode` refuses any other length.
pub const CUSTODY_KEM_EK_BYTES: usize = 1184;
/// The widest framed seat this protocol emits or admits: ML-DSA-65 pubkey (1,952) + signature (3,309)
/// + the fixed header (33 + 32 + 1,184) + framing — ~6.6 KB. `wire` refuses to frame a wider one and
/// `decode` refuses to admit one, so a retained seat request is bounded by this constant.
pub const MEMBERSHIP_BOND_WIRE_MAX: usize = 8192;

/// The fixed-width head of a membership bond: the member's bridge-custody points, so the reserve address
/// (the LIVE bonded set's key-aggregate) can include this member the moment the seat lands.
///
/// CLASSICAL-CRYPTO-EXEMPT: these are the member's FOREIGN-chain custody points (the BTC and XMR reserve
/// key shares) — the marked external-bridge carve-out. They sign nothing on THIS chain; the seat itself is
/// authorised by the ML-DSA-65 signature in the payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MembershipBondHeader {
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant CUSTODY_POINT_BYTES (=33), enforced in
    /// `decode`; one seat is one object, so this cannot grow with height, notes or peers.
    pub secp33: Vec<u8>,
    pub ed32: [u8; 32],
    /// The member's ML-KEM-768 encapsulation key — where a peg-in executor SEALS the custodian-only
    /// transition delta (`crate::peg_attest::seal_delta_to`), so this custodian can re-derive and attest
    /// the commitments it is asked to sign without the delta ever crossing the wire in the clear.
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant CUSTODY_KEM_EK_BYTES (=1184), enforced in `decode`.
    pub kem_ek: Vec<u8>,
    /// ⛔ DB-258b — a SIGNER-CHOSEN value, fresh per seat request (`fresh_seat_nonce`) and signed with the rest, so each
    /// request is a distinct ONE-SHOT RIGHT (`seat_right_nf`): a validator that left asks again with a new request, and
    /// an old request re-carried after it left names a right the chain already retired.
    pub nonce: [u8; 32],
}

impl MembershipBondHeader {
    /// The digest the membership signature binds — every byte that reaches the custody registry.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/membership-seat-header/v2");
        h.update(&self.secp33);
        h.update(&self.ed32);
        h.update(&self.kem_ek);
        h.update(&self.nonce);
        *h.finalize().as_bytes()
    }
}

/// ⛔⛔⛔ DB-258b — THE SEAT REQUEST'S ONE-SHOT RIGHT: `H(domain ‖ id ‖ header digest)`, DERIVABLE from the object (the
/// mint's issuance right, `asset_tx::issue_right_nf`, in a seat's clothes). The request's transaction carries it in its
/// lane (`chain_object::object_own_nullifiers`, checked at the pool door by `wrapper_binds_object`) and the block that
/// seats the validator must carry it in ITS lane (`apply_chain_membership_bond`), so the sparse nullifier set retires
/// it exactly once. MEASURED (the DB-258b pin): without it, anyone re-carried a validator's OLD seat object after it
/// unbonded and put it back into the finality and custody tally against its will.
#[must_use]
pub fn seat_right_nf(id: &[u8; 32], header: &MembershipBondHeader) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"musdm.validator.seat.v1");
    h.update(id);
    h.update(&header.digest());
    crate::cover::canonical_tag_of_hash(h.finalize().as_bytes())
}

/// DB-258b — a fresh seat-request nonce, by the crate's own entropy idiom (both halves of a throwaway ML-KEM-768 keypair
/// are CSPRNG-minted, so their hash is uniform; the same idiom mints the node's DA secret). Never a fixed value: two
/// requests with one nonce are one right, and the second could never seat.
#[must_use]
pub fn fresh_seat_nonce() -> [u8; 32] {
    let (ek, dk) = crate::pqkem::keypair();
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/membership-seat-nonce/v1");
    h.update(&ek);
    h.update(&dk);
    *h.finalize().as_bytes()
}

/// The EXACT payload type: the header plus the raw PQ public key and its ML-DSA-65 signature.
pub type MembershipBondPayload = (MembershipBondHeader, Vec<u8>, Vec<u8>);

/// The canonical payload bytes (unframed), or `None` if they cannot be produced. Fail-closed, never
/// defaulted — empty bytes would frame cleanly and authorise nothing, and the caller would publish them.
#[must_use]
pub fn encode(header: &MembershipBondHeader, pubkey: &[u8], sig: &[u8]) -> Option<Vec<u8>> {
    postcard::to_stdvec(&(header, pubkey, sig)).ok()
}

/// The FRAMED blob — the one form this object travels in.
#[must_use]
pub fn wire(header: &MembershipBondHeader, pubkey: &[u8], sig: &[u8]) -> Option<Vec<u8>> {
    let framed = crate::chain_object::frame(
        crate::chain_object::Class::MembershipBond,
        &encode(header, pubkey, sig)?,
    );
    if framed.len() > MEMBERSHIP_BOND_WIRE_MAX {
        return None; // wider than any honest seat — never framed
    }
    Some(framed)
}

/// Refuses rather than guesses. Strict full-consumption decode, so `encode(a) || junk` is not a second,
/// differently-identified copy of one seat. The PQ material is fixed-width by the ML-DSA-65 parameter
/// set (`MlDsaVerifier::verify` refuses any other length), so a decoded seat carries no term in height,
/// supply or peer count.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<(MembershipBondHeader, Vec<u8>, Vec<u8>)> {
    if payload.len() > MEMBERSHIP_BOND_WIRE_MAX {
        return None; // wider than any honest seat — refused before it is parsed
    }
    let (header, pubkey, sig) = decode_exact::<MembershipBondPayload>(payload)?;
    if pubkey.is_empty() || sig.is_empty() {
        return None;
    }
    if header.secp33.len() != CUSTODY_POINT_BYTES {
        return None; // not a compressed custody point
    }
    if header.kem_ek.len() != CUSTODY_KEM_EK_BYTES {
        return None; // not an ML-KEM-768 encapsulation key
    }
    Some((header, pubkey, sig))
}

/// The validator id a seat admits — `H(pubkey)`, RECOMPUTED by every node, never a claimed id.
#[must_use]
pub fn validator_id(pubkey: &[u8]) -> [u8; 32] {
    crate::pqauth::pubkey_id(pubkey)
}

/// ⭐ SELF-VERIFYING: the signature must be the key-holder's over THIS id's membership message AND this
/// header's digest. Every node reaches the same verdict from the object alone, and a re-framed seat with
/// substituted custody points or a substituted encapsulation key fails here.
#[must_use]
pub fn is_authorised(
    header: &MembershipBondHeader,
    pubkey: &[u8],
    sig: &[u8],
    v: &dyn crate::pqauth::PqVerifier,
) -> bool {
    v.verify(
        pubkey,
        &crate::pqauth::validator_membership_msg(&validator_id(pubkey), &header.digest()),
        sig,
    )
}

/// What applying a membership-bond object did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MembershipApply {
    /// Not a membership bond — left entirely alone.
    NotMembershipBond,
    /// The seat landed: the member is in this node's validator set with membership weight.
    Seated,
    /// Already seated — a re-applied block never double-seats.
    AlreadySeated,
    /// Refused before anything moved, with the reason a node can act on.
    Refused(&'static str),
}


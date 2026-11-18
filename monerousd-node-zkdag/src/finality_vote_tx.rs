// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔⛔⛔ G2 (lane a 2026-10-22) — `Class::FinalityVote`: A FINALITY VOTE IS A CHAIN OBJECT, BECAUSE FINALITY IS A CHAIN FACT.
//!
//! ## What this replaces, and why it was a divergence
//! Both finality-vote doors (`Node::submit_finality_vote`, `Node::ingest_finality_vote_gossip`) TALLIED a vote the moment
//! it was received, and no block carried a vote. A node's `(finalized_height, finalized_block)` was therefore a function
//! of which votes had been DELIVERED to it, not of the chain it held: MEASURED by the replica census (`finality` DIFFERS
//! 39/39, n0 at 12 while n1 at 13 on the same blocks, scratchpad/night/g1-minednfs-harness-3-20261022.log:2482) and by the
//! RED pin `node::pins::two_nodes_holding_the_same_blocks_read_the_same_finality_whichever_of_them_heard_the_votes`
//! (A reads (1, Some), B reads (0, None), both holding every block). Finality drives the fork-choice floor and the DA
//! reorg-purge boundary, so two honest nodes holding one chain disagreed about what was final on it.
//!
//! ## The borrowed shape
//! Ethereum carries attestations IN THE BLOCK BODY and every node tallies them at block processing; Tendermint's commit for
//! height h rides block h+1. Hearing a vote only POOLS it (Bitcoin's rule: the pool is local, the block is authoritative).
//! The object rides `Block::bond_set` — the header-bound validator lane the seat, the unbond and the equivocation evidence
//! already ride (`Class::Equivocation`, DB-266) — and is tallied at the carrying body's GRAFT, at the one site every
//! body-keeping door passes through (`Node::remember_unfolded_block` → `Node::apply_carried_finality_votes`). Not at the
//! fold: MEASURED on the 3-node sim, the fold trails the tip by `RECORD_FOLD_DEPTH_DEFAULT` (32) blocks, so a fold-side
//! tally left finality 64 levels behind the tip (finalized 21 at tips 115, g2-finality-harness-20261022.log:4767); a vote
//! moves no value, so unlike a slash it needs no canonical pre-state step. The tally is commutative (a set per block; the
//! finalized pair is the max); only an equivocator's two votes are first-wins by arrival, and two honest nodes counting
//! different halves of such a pair finalize two blocks at one height only with ≥ 1/3 of the weight Byzantine — the bound
//! every ≥ 2/3 quorum already assumes (its evidence slashes it, DB-266).
//!
//! ## The object
//! ONE `VoteCert`: `(pubkey, block, height, sig)`. Every node verifies the ML-DSA-65 signature over
//! `pqauth::finality_vote_msg(block, height)` under the object's one pubkey and RECOMPUTES the voter id as `H(pubkey)`;
//! the carried validator set says whether that id holds finality weight; the node's OWN DAG says whether `block` sits at
//! `height` (`Node::finality_vote_binds_to_dag`). The pubkey rides the object (the set holds ids, not keys): ~5.4 KB.
//!
//! ## §9.6 — THE NEW-DOOR CHECKLIST (parity door: the `Class::Equivocation` arm of `apply_bond_set`)
//! 1. Proof of work: the carrying block's, verified at its own ingest door before any lane applies.
//! 2. The object's own proof: the ML-DSA-65 signature, verified HERE from the object's bytes (`is_authorised`), on every
//!    folding node — never a peer's word.
//! 3. Value: a vote mints, moves and burns nothing (`carried_note_payloads` → no note; `wrapper_binds_object` refuses a
//!    wrapper claiming one). It moves the finality floor only, and only by ≥ 2/3 of the carried set's weight.
//! 4. Replay: a vote already tallied re-tallies idempotently (`FinalityTracker::record_verified_vote`: same block, same
//!    height → no change); the pool refuses one the chain already carries (`chain_object_already_settled`).
//! 5. Bounded work: one strict decode and one signature verify per entry; entries are bounded by the bond lane's own
//!    bound; the tally maps are bounded by `FINALITY_VOTE_RETENTION`.
//! 6. Parity: the Equivocation arm's checks — strict decode, exact-width key and signature, signature verified under the
//!    recomputed id, applied from the carried lane on every node, the verdict said — each is here. The equivocation arm
//!    needs no held block; a vote DOES (it finalizes one), so the DAG binding is this door's extra check, not a missing one.
//!    The one difference, the step: a slash applies at the fold against a pre-state set because it moves a bond; a vote
//!    moves nothing and applies at the graft (above).
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;
use crate::validator::VoteCert;

/// The widest honest vote: one ML-DSA-65 public key (1,952 B), one signature (3,309 B), a block id, a height and postcard
/// framing — about 5.4 KB. A payload wider than 8 KiB is refused before it is parsed.
pub const FINALITY_VOTE_WIRE_MAX: usize = 8 * 1024;
/// ML-DSA-65 public key width (FIPS 204) — a key of any other width is not one, and is refused at decode.
pub const ML_DSA_65_PK_LEN: usize = 1_952;
/// ML-DSA-65 signature width (FIPS 204).
pub const ML_DSA_65_SIG_LEN: usize = 3_309;

/// The canonical encoding of one vote: the `VoteCert`'s own postcard form (the same bytes `VoteCert::to_wire` gossips).
#[must_use]
pub fn encode(cert: &VoteCert) -> Vec<u8> {
    cert.to_wire()
}

/// Frame a vote as a `Class::FinalityVote` object — the one publication path. `None` for a cert no honest voter signs
/// (wrong key or signature width, or wider than the cap).
#[must_use]
pub fn wire(cert: &VoteCert) -> Option<Vec<u8>> {
    if cert.pubkey.len() != ML_DSA_65_PK_LEN || cert.sig.len() != ML_DSA_65_SIG_LEN {
        return None;
    }
    let framed = crate::chain_object::frame(Class::FinalityVote, &encode(cert));
    if framed.len() > FINALITY_VOTE_WIRE_MAX {
        return None;
    }
    Some(framed)
}

/// Strict decode: one encoding (`decode_exact`), exact ML-DSA-65 key and signature widths, under the cap.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<VoteCert> {
    if payload.len() > FINALITY_VOTE_WIRE_MAX {
        return None;
    }
    let cert = decode_exact::<VoteCert>(payload)?;
    if cert.pubkey.len() != ML_DSA_65_PK_LEN || cert.sig.len() != ML_DSA_65_SIG_LEN {
        return None;
    }
    Some(cert)
}

/// ⭐ SELF-VERIFYING FROM THE OBJECT ALONE: `Some(voter id)` iff the signature is the key-holder's over this
/// `(block, height)`. The id is `H(pubkey)`, recomputed here — never a claimed id.
#[must_use]
pub fn is_authorised(cert: &VoteCert, v: &dyn PqVerifier) -> Option<[u8; 32]> {
    if !v.verify(&cert.pubkey, &crate::pqauth::finality_vote_msg(&cert.block, cert.height), &cert.sig) {
        return None;
    }
    Some(crate::pqauth::pubkey_id(&cert.pubkey))
}

/// What applying a carried vote did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FinalityVoteApply {
    /// Not a finality vote object — left entirely alone.
    NotFinalityVote,
    /// Tallied; the block is not final yet (or was already).
    Counted,
    /// Tallied, and it pushed its block to ≥ 2/3 of the finality weight.
    Finalized,
    /// Refused before anything moved, with the reason a node can act on.
    Refused(&'static str),
    /// ⭐ G2b — verified and KEPT, not judged yet: this node's fold cursor is below `height − FINALITY_SEAT_ACTIVATION_DELAY`,
    /// so the set active at the voted height is not yet known here; `Node::judge_deferred_votes` tallies it when it is.
    Deferred,
}


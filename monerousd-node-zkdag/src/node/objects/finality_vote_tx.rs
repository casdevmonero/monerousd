// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::finality_vote_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `finality_vote_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::finality_vote_tx::*;
use crate::chain_object::{decode_exact, unframe, Class};
use crate::pqauth::PqVerifier;
use crate::validator::VoteCert;

/// ⭐⭐⭐ THE GRAFT-SIDE DOOR — every node that keeps a body carrying a vote verifies it from the object's own bytes under
/// the node's pinned finality verifier (fail-closed without one, exactly like the receipt doors), checks the voter holds
/// finality weight in the CARRIED set and that the voted block sits at the voted height in THIS node's DAG, then tallies
/// it through the one tracker. A conflicting vote by the same key at the same height is NOT counted and is queued as
/// equivocation evidence for publication (DB-266), never slashed here.
pub fn apply_chain_finality_vote(node: &mut crate::node::Node, blob: &[u8]) -> FinalityVoteApply {
    let Some((class, payload)) = unframe(blob) else {
        return FinalityVoteApply::NotFinalityVote;
    };
    if class != Class::FinalityVote {
        return FinalityVoteApply::NotFinalityVote;
    }
    let Some(cert) = decode(payload) else {
        return FinalityVoteApply::Refused("the payload is not one canonical finality vote");
    };
    let voter = match node.verify_finality_vote(&cert) {
        Ok(voter) => voter,
        Err(crate::validator::FinalityVoteOutcome::Unauthenticated) => {
            return FinalityVoteApply::Refused("the signature is not the key-holder's over this block and height")
        }
        // ⛔ G2b (lane a 2026-10-22): the two refusal arms are SAID APART — the restart census read 48 refusals of this
        // door at a resume under one conflated line (g1-reward-harness-20261022.log:3493–3667), and a measurement that
        // cannot tell "the set this node's fold has applied holds no seat for this key" from "the DAG does not hold the
        // block at that height" cannot attribute the class. One extra map read, on the refusal path only.
        Err(_) if node.validators().finality_weight_of_at(&crate::pqauth::pubkey_id(&cert.pubkey), cert.height) == 0 => {
            return FinalityVoteApply::Refused(
                "the voter holds no finality weight in the set this node's fold has applied (G2b: the denominator is the local fold cursor)",
            )
        }
        // ⭐ A-F82 (lane af58, 2026-11-16): a vote whose signature and weight passed, for a block this node does NOT HOLD YET,
        // is KEPT and judged when the block arrives (`Node::defer_vote_awaiting_block`, re-judged by `judge_deferred_votes`),
        // never dropped. Voters vote at their own tip's level (vote_guard::SETTLE_MIN = 0), so a carried vote often lands
        // before the block it names; dropped, it was lost for good and the quorum starved (MEASURED verifier rig, main
        // b213c710, 14:36: nodes refused 14/48/54 carried votes with this door's line, finality stood at 256 for 10+ min with
        // three seats of weight 1). BORROWED: Bitcoin Core's orphan pool (a transaction whose input is not yet known is held,
        // bounded, and re-tried when its parent arrives). A vote for a block at ANOTHER height is still refused here.
        Err(_) if node.dag().get(&cert.block).is_none() => {
            node.defer_vote_awaiting_block(cert);
            return FinalityVoteApply::Deferred;
        }
        Err(_) => return FinalityVoteApply::Refused("the voted block is not at the voted height in this node's DAG"),
    };
    match node.tally_carried_finality_vote(cert, voter) {
        crate::validator::VoteRecord::Finalized => FinalityVoteApply::Finalized,
        crate::validator::VoteRecord::Counted => FinalityVoteApply::Counted,
        crate::validator::VoteRecord::Equivocation { .. } => {
            FinalityVoteApply::Refused("a second block by this key at this height — queued as equivocation evidence")
        }
        crate::validator::VoteRecord::NoWeight => FinalityVoteApply::Refused("no weight at this height (below retention, or unseated)"),
        crate::validator::VoteRecord::Deferred => FinalityVoteApply::Deferred,
    }
}

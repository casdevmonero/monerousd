// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::bridge_credit_tx` that reads or moves the node: its apply at the fold and the verdicts that
//! read node state, moved here from `bridge_credit_tx.rs` byte for byte (lane dcash, 2026-11-11, stage A of the node split) so the object
//! module itself never reaches up into the node and can live in a crate of its own.

#![allow(unused_imports)]
use crate::bridge_credit_tx::*;
use serde::{Deserialize, Serialize};

/// THE GRAFT-SIDE DOOR for bridge credits — the RECONCILE half, run over a grafted block's pooled
/// transaction blobs (its production caller is `ingest_block_preverified`'s per-block apply, beside
/// `retire_orders_burned_by`).
///
/// ⭐ v32 (item 8c) — THE VALUE PATH IS THE BLOCK, NOT THIS FUNCTION. A credit transaction's note rides
/// `PqTx::output_notes` into `Block::output_notes` (sealed before the mine, bound by the PoW), and its
/// owner filing rides the block's carried account targets — so EVERY node, pooled or not, applies the
/// credit through the ONE shared record path at graft. This door therefore writes NO record and files NO
/// target: an earlier draft called `record_note_payload(tip_height, note)` here, which is a SECOND record
/// of the same note at a node-local address — the exact "same record, different bytes/addresses on two
/// nodes" divergence class this file's history documents. One object, one apply path.
///
/// What remains here, and is genuinely graft-side work: RECONCILING the accepting node's own STAGED copy
/// (`stage_credit_note` → `pending_credit_notes`) with the published copy the block just delivered — the
/// staged duplicate is dropped, so a credit that was both staged locally and published as a transaction
/// lands exactly ONCE (the "ONE credit object — never a second beside it" law). `AlreadyHeld` names a
/// commitment some earlier block already recorded (a replayed deposit): nothing is credited again — the
/// unspent tree is position-keyed by the note, so a duplicate receive fail-closes there too.
///
/// ⛔⛔⛔ §9.6 ANSWERED FOR THIS DOOR — DOOR AUDIT 2026-09-07 (family B). This is a DESTRUCTION door, not
/// a mint one: its only state effect is `unstage_credit_note`, and `stage_credit_note` is the lane every
/// faucet drip, publish-refused peg-in, unbond return, executor credit and stranded-note re-carry rides.
///  1. PROOF OF WORK — none is asked and none is due: the door judges an OBJECT, not a header, and its
///     production caller (`ingest_block_preverified`'s per-block apply) has already accepted the block.
///  2. PROOF / SIGNATURE — `chain_object::admissible` is asked RIGHT HERE, on this path, which is the same
///     function the graft NOTE door (`graft_admitted_notes`) asks. Not taken on trust from upstream.
///  3. CONSERVATION — the door creates nothing (it writes no record and files no target); what it can
///     DESTROY is now gated by the same verdict that decides whether the object's own notes may land.
///  4. REPLAY — a repeat of these exact bytes is idempotent: `unstage_credit_note` is a `retain`, so a
///     second pass over the same commitment removes nothing that is not already gone.
///  5. BOUNDED WORK — one `unframe`, one `decode`, one `admissible` call and one `retain` over
///     `pending_credit_notes`, which drains into the very next produced block. No walk keyed by height.
///  6. PARITY WITH THE DOOR IT PARALLELS — the sibling is `graft_admitted_notes`, which STRIPS every
///     wrapper note commitment of an object `admissible` refuses. It ran that filter; this reconcile loop
///     ran over the RAW pooled blobs and consulted nothing, so the refusal and the destruction disagreed.
///
/// ROOT-LAYER: the verdict is PRODUCED here — this function is where a blob becomes "a credit that may
/// retire a staged copy", and every caller (the graft-side reconcile loop and any future one) passes
/// through it. Fixing the caller's loop instead would leave the class open for the next writer, which is
/// precisely the failure `graft_admitted_notes`' own doc records ("the record path re-recorded what the
/// door had stripped").
/// MEASURED: 2026-09-07, `a_credit_the_mint_door_refuses_cannot_retire_a_staged_credit_on_either_party` —
/// before, FAILED with `verdict Credited(1000000000001)` on node_a and the honest staged credit gone
/// (0 passed; 1 failed); after, ok (1 passed; 0 failed) and the staged credit survives on both parties.
/// MUST-STAY-GREEN: every honest publisher round-trip in this module's tests — in particular
/// `a_rogue_producers_injected_chunk_credits_nothing_on_the_peer` (the justified credit must still apply
/// on the peer: fail-closed on the bad item, never on the block) and the faucet/peg-in credit paths whose
/// objects are within the chain's genesis-derived open-mint allowance and therefore admissible.
pub fn apply_chain_bridge_credit(node: &mut crate::node::Node, blob: &[u8]) -> CreditApply {
    // The class is READ, never guessed: only a framed BridgeCredit blob is a credit (`wire()` is the one
    // encoding on the wire; a bare postcard blob is not classifiable and is left alone).
    let Some((class, payload)) = crate::chain_object::unframe(blob) else {
        return CreditApply::NotCredit;
    };
    if class != crate::chain_object::Class::BridgeCredit {
        return CreditApply::NotCredit;
    }
    let Some(c) = BridgeCreditTx::decode(payload) else {
        return CreditApply::NotCredit;
    };
    let Some(cm) = c.note_cm() else {
        return CreditApply::NotCredit;
    };
    // ⛔ THE MINT DOOR DECIDES, HERE, BEFORE ANYTHING IS RETIRED. An object whose notes the graft door
    // strips has no standing to retire the honest staged copy that shares its commitment — the refusal and
    // the destruction must agree, or the credit exists in NEITHER place. Same function, same parameters and
    // therefore the same verdict as `graft_admitted_notes`. A refused object is simply not a credit as far
    // as this door is concerned, so it is reported `NotCredit` and changes no state at all.
    // ⭐ THE AUTHORITY TRAVELS WITH THE RULE. The quorum verdict is computed from THIS node's folded
    // bonded set and handed to the door, so this door and the graft door reach the same answer on the
    // same bytes — see `credit_attested_by_bonded_quorum` for why that identity is the whole point.
    let credit_attested = credit_attested_by_bonded_quorum(node.validators(), blob);
    if !crate::chain_object::admissible(
        blob,
        node.params().order_fill_fee_bps,
        node.params().genesis_mint_allowance(),
        credit_attested,
    ) {
        // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
        eprintln!(
            "[credit-reconcile] ⛔ REFUSE: the mint-authority door refuses this object, so it cannot \
             retire anything this node has staged. Nothing unstaged."
        );
        return CreditApply::NotCredit;
    }

    // ⭐⭐⭐ WHO MAY ISSUE A CREDIT — THE BONDED-THRESHOLD ARM, LANDED, AND IT LIVES IN THE DOOR.
    //
    // ⛔⛔⛔ UNTIL THIS EXISTED, NOTHING ASKED. `chain_object::admissible`'s `Class::BridgeCredit` arm
    // decoded the payload and compared `amount` to `genesis_mint_allowance`, and that was the whole
    // authority: `harness::value_creation` filed it as `Authority::Missing` — *"NOTHING asks who may
    // issue a credit … Safe on a value-bearing network ONLY because the allowance is 0 there, which is a
    // fail-closed default and not an authority."* An allowance of 0 does not authorise the bridge
    // either — it makes the class UNSATISFIABLE, so a real deposit could never be credited at all.
    //
    // ⭐ EITHER AUTHORITY, NEVER NEITHER: within this chain's genesis-derived open-mint allowance (the
    // open-mint networks, unchanged) **or** attested by a ≥2/3 bonded quorum. That disjunction is now a
    // line inside `admissible` itself, fed by the `credit_attested` computed above — NOT a second check
    // sitting here. ⛔ A check that lived only here would bind only this door: the graft door calls
    // `admissible` and never reaches this function, which is exactly the hole
    // `a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body` names — *"the mint-authority
    // rule binds only the POOL door, and a producer that skips its own door mints on every honest peer at
    // graft."* One rule, one call, every door.
    reconcile_attested_credit(node, &cm, c.amount)
}

/// ⭐ DB-274 P4 (§8.11 item 6) — the reconcile HALF alone, for a credit whose weight verdict has ALREADY been taken: at
/// its fold, in the step's canonical pre-state (`Node::credit_decide_at_fold`). The fold runs this only after the step
/// succeeds, when the bonded set may already have moved to the step's POST-state, so it must never re-tally. It
/// retires the node's own staged copy of the same commitment, so a credit both staged here and carried by a block lands
/// exactly once.
pub(crate) fn reconcile_attested_credit(node: &mut crate::node::Node, cm: &[u8; 32], amount: u64) -> CreditApply {
    let had_record_before = node.holds_record_with_cm(cm);
    let _staged_copy_dropped = node.unstage_credit_note(cm);
    if had_record_before {
        return CreditApply::AlreadyHeld;
    }
    CreditApply::Credited(amount)
}

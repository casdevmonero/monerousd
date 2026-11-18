// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE VALUE-CREATION CENSUS — EVERY SITE THAT BRINGS VALUE INTO EXISTENCE, AND THE THREE
//! QUESTIONS EACH ONE MUST ANSWER.
//!
//! ⛔⛔⛔ WHY THIS EXISTS, IN THE USER'S OWN WORDS: *"are there any more missing defi functionality like
//! creator id that allowed infinite mint of defi assets? We need the harness/guard to be able to
//! automatically catch holes like this ecosystem wide because infinite mint is also a funds loss hole."*
//!
//! THE RECORD THAT PROVES THE POINT. Within one day, the SAME class of hole was found three times, each
//! time by hand, each time in a path already recorded as proven:
//!
//! * **§AT** — `AssetCreateTx` had no creator and `AssetMintTx` no signature. ANYONE could mint unlimited
//!   supply of ANYONE's token. MEASURED: `other_key=Minted(1)`. Found because the user asked who owns an
//!   asset. **AUTHORITY was missing.**
//! * **§AV** — with the creator gate landed, the creator could still re-issue the same NFT without bound.
//!   MEASURED: `creator_again=Minted(1)`. **ONCE was missing.**
//! * **§AX** — with both landed, they were enforced in `Node::publish_asset_mint` (the door an HONEST
//!   user walks through) and in `asset_tx::apply_chain_asset_object` (**zero production callers**). The
//!   GOSSIP door — the only one an attacker uses — asked neither. **AUTHORITY was missing where it
//!   counted.**
//!
//! Three separate hand-found holes, one shape. The instrument that would have caught all three on the day
//! each mechanism landed is a census that asks every value-creating site the same three questions and
//! refuses to let a `Missing` answer go unfiled.
//!
//! ⭐⭐⭐ THE THREE QUESTIONS — read off `Node::execute_stake` (DB-237), a site that answers all three
//! soundly and is therefore the template:
//!
//! 1. **AUTHORITY — who may create this value?** Stake claim: the stake carrier (the staker's key opens the
//!    spent note) plus its membership at the fold. An answer must be enforced at the door an ADVERSARY uses,
//!    not only at the publisher. §AX is the whole lesson.
//! 2. **AMOUNT — is it derived, or merely declared?** Stake claim: `floor(v·rate·Δ/D)`, computed in-circuit
//!    and pinned to the chain's governance rate and the block's epoch by every node. A DECLARED amount is sound only when the authority signature or a ZK carrier
//!    BINDS it, so that inflating it invalidates the authority.
//! 3. **ONCE — what stops the identical creation happening twice?** Yield claim: the stake nullifier.
//!    Without an answer here a site is infinitely inflatable BY THE PARTY THE GATE ALREADY TRUSTS, which
//!    is precisely why §AT's fix did not close §AV.
//!
//! ⛔ A CROSS-NODE PIN PROVES CARRIAGE, NOT AUTHORISATION (§AT). `harness::e2e_claims` asks whether value
//! can MOVE to a second party; this asks whether it may be CREATED at all. A class can be green there and
//! infinitely mintable here — `AssetMint` was, for a day.

use std::collections::BTreeSet;

/// WHO may create this value, and — the part §AX turned on — WHERE that is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// A signature or ZK carrier checked on the GOSSIP path (`chain_object::admissible`), so a
    /// transaction an attacker builds themselves is judged by it. Names the symbol that decides.
    AtTheGossipDoor(&'static str),
    /// A ≥2/3 bonded-weight attestation tallied at apply, where the door holds the validator set.
    BondedThreshold(&'static str),
    /// ⭐ §BA — checked at the GRAFT door, on every node, against evidence THE BLOCK ITSELF CARRIES:
    /// a proof the peer verifies, a framed object the peer re-admits, or this node's own O(1) state.
    ///
    /// ⛔ A DISTINCT ANSWER FROM `AtTheGossipDoor`, AND THE DIFFERENCE IS THE WHOLE OF §BA. The gossip
    /// door judges a transaction an attacker submits — but under the constant-256 cover a peer never
    /// receives most bodies, so the gossip door is silent on a peer's blocks. This one is not: it runs
    /// on every grafted block, holding no body, and refuses what it cannot justify.
    AtTheGraftDoor(&'static str),
    /// ⭐ DB-274 P4b — checked at the block's canonical FOLD, on every node, in the fold step's pre-state: a door that
    /// needs chain state (a quorum tally, a carrier against the committed supply or pool) decides there, and a refused
    /// object's notes leave the record (`Node::fold_strip_row`) before anything can spend them (a spend needs a FOLDED
    /// record, DB-358). Names the symbol that decides.
    AtTheFold(&'static str),
    /// ⛔ NOTHING ASKS. Names why. This is §AT's state, and it must appear in `FILED_OPEN`.
    Missing(&'static str),
}

/// Is the created amount COMPUTED by every node, or declared by the creator?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    /// Derived from chain state by every node — the creator cannot choose it. The strongest answer.
    DerivedByEveryNode(&'static str),
    /// Declared, but BOUND into the authority (signed over, or a ZK carrier's public input), so
    /// inflating it invalidates the authority. Sound.
    BoundIntoTheAuthority(&'static str),
    /// ⛔ Declared and unbound: the creator picks the number and nothing checks it.
    Missing(&'static str),
}

/// What stops the identical creation happening a second time?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Once {
    /// A note is deleted from the unspent tree (§AQ). The chain's own spend authority, no new state.
    DeletionTransition(&'static str),
    /// A nullifier the site derives and the lane retires.
    Nullifier(&'static str),
    /// The created commitment is itself the identity, and one commitment is credited once.
    CommitmentIsTheIdentity(&'static str),
    /// ⛔ NOTHING STOPS A SECOND. This is §AV's state.
    Missing(&'static str),
}

/// ⭐⭐⭐ THE FOURTH QUESTION — DOES THE CREATION **TRAVEL**?
///
/// ⛔⛔⛔ THE CENSUS ASKED WHO / HOW MUCH / ONCE AND NEVER ASKED THIS, SO A SITE COULD ANSWER ALL THREE
/// PERFECTLY AND STILL BE A LOCAL MUTATION. That is the cardinal this project has paid for twice — *every
/// value-moving transition MUST be a chain object the block carries, NEVER a local mutation, however
/// soundly the local node verified it* — and both times the census was green while it happened.
///
/// MEASURED 2026-09-16: `Node::peg_in_confidential` — the path where depositing BTC/XMR brings USDm into
/// existence, the primary issuance route of this chain — ends in `record_account_target` +
/// `record_note_payload`, both node-local, with no `ingest_tx`, no framed object, and a peg commitment
/// advanced on that node only. It answers authority, amount and once well; it does not travel. It was in
/// NO census, so it appeared on no list of what was left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Travels {
    /// The created value rides a transaction or a header-bound set every peer applies. Names the publish.
    AsAChainObject(&'static str),
    /// ⛔ NODE-LOCAL. The note exists where it was minted and nowhere else; peers hold nothing for it,
    /// and any commitment this site advanced has diverged from theirs.
    Missing(&'static str),
}

/// One site where value comes into existence.
#[derive(Debug, Clone, Copy)]
pub struct Site {
    /// The production symbol or chain-object class this describes.
    pub name: &'static str,
    pub authority: Authority,
    pub amount: Amount,
    pub once: Once,
    /// ⭐ THE FOURTH ANSWER — see [`Travels`]. A site that answers the first three and not this one is a
    /// local mutation with good paperwork.
    pub travels: Travels,
}

impl Site {
    /// Does this site answer all FOUR questions? (`travels` was added 2026-09-16 — see [`Travels`].)
    pub fn is_closed(&self) -> bool {
        !matches!(self.authority, Authority::Missing(_))
            && !matches!(self.amount, Amount::Missing(_))
            && !matches!(self.once, Once::Missing(_))
            && !matches!(self.travels, Travels::Missing(_))
    }
    /// The unanswered questions, named — what a failure prints.
    pub fn gaps(&self) -> Vec<String> {
        let mut g = Vec::new();
        if let Authority::Missing(w) = self.authority {
            g.push(format!("AUTHORITY: {w}"));
        }
        if let Amount::Missing(w) = self.amount {
            g.push(format!("AMOUNT: {w}"));
        }
        if let Once::Missing(w) = self.once {
            g.push(format!("ONCE: {w}"));
        }
        if let Travels::Missing(w) = self.travels {
            g.push(format!("TRAVELS: {w}"));
        }
        g
    }
}

/// ⭐⭐⭐ THE REGISTER. Every site that creates value on this chain, with its three answers.
///
/// ⛔ ADDING A SITE HERE IS NOT OPTIONAL: `every_value_creating_class_is_in_the_census` derives the class
/// list from `src/chain_object.rs` itself, so a new class that carries a note fails this module until its
/// three answers are written down.
pub const SITES: &[Site] = &[
    // ── THE TEMPLATE ────────────────────────────────────────────────────────────────────────────────
    Site {
        name: "Node::execute_stake",
        authority: Authority::AtTheGraftDoor(
            "the stake carrier proves the staker OWNS the spent note (its key opens the leaf, the nullifier is its own) and \
             the one-step membership carrier proves the note on chain; both re-verified at the fold on every node",
        ),
        amount: Amount::DerivedByEveryNode(
            "r = floor(v·rate·Δ/D) IN-CIRCUIT from the hidden staked value and start epoch, at the chain's governance rate \
             and the block's own epoch (both checked at the fold) — never declared",
        ),
        once: Once::Nullifier("the input note's nullifier is the object's own lane tag; the spent SET refuses a second use"),
        travels: Travels::AsAChainObject(
            "⭐ DB-237 — it publishes a framed stake object (the `YieldClaim` class tag) through the marking door with the \
             input's nullifier on the transaction's own lane, and every node applies it at its block's canonical fold \
             (`stake_tx::apply_chain_stake` → `Node::apply_stake_at_fold`).",
        ),
    },
    // ── ASSETS — the three holes this census was built after ────────────────────────────────────────
    // ── THE PRIMARY ISSUANCE ROUTE, AND IT WAS IN NO CENSUS AT ALL ─────────────────────────────────
    //
    // ⛔⛔⛔ THIS IS HOW USDm COMES INTO EXISTENCE. A depositor sends BTC or XMR, a ≥2/3 threshold
    // attestation authorises an amount, and a confidential note is credited. It is the route that
    // matters most for real funds — and until 2026-09-16 it appeared in NEITHER this census NOR the
    // end-to-end register, so it could never show up on any list of what was left. The completeness
    // rule could not have caught it either: it derived the site list from `Class::` variants in
    // `chain_object.rs`, and a value-creating RPC HANDLER is not a chain-object class.
    // That is why `every_local_note_minting_function_is_in_the_census` now derives from
    // `record_note_payload` callers instead — the one primitive that brings a note into local existence.
    Site {
        name: "Node::peg_in_confidential",
        authority: Authority::BondedThreshold(
            "peg::verify_confidential_peg_in tallies the ≥2/3 mint attestation over the deposit",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "`mint_authorized` is the attested amount and `mint_carrier` proves the credited note's \
             commitment OPENS to exactly it — a note sealed for more is refused",
        ),
        once: Once::CommitmentIsTheIdentity(
            "the deposit id retires in the peg's spent-deposit set, and the credited commitment is \
             credited once",
        ),
        travels: Travels::AsAChainObject(
            "⭐ §CS CLOSED — it publishes a framed `Class::PegIn` through `ingest_tx`, and every peer \
             re-runs `peg::peg_in_confidential` from the object's own bytes at graft \
             (`peg_in_tx::apply_chain_peg_in`). Before this it ended in `record_account_target` + \
             `record_note_payload` with the peg commitments advanced on ONE node, so the depositor's \
             USDm existed nowhere else and the same attested deposit could be re-pegged per node.",
        ),
    },
    Site {
        name: "Class::YieldClaim",
        authority: Authority::AtTheGraftDoor(
            "DB-237: the stake carrier (the input opens under a stake tag or USDm under the staker's key) and the one-step \
             membership carrier at the `MemberDoor::Fold` door, re-verified at the canonical fold on every node",
        ),
        amount: Amount::DerivedByEveryNode(
            "the stake gate computes r = floor(v·rate·Δ/D) exactly (a USDm input has Δ = 0 forced); the supply step opens the \
             SAME `reward_commit` and refuses any mint the reserve's surplus does not back",
        ),
        once: Once::Nullifier(
            "the input note's nullifier is the object's own lane tag (the spent SET), and the principal is re-staked from \
             the block's own epoch — no interval is paid twice",
        ),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::execute_stake` frames it and pools it; `stake_tx::apply_chain_stake` is what \
             every node runs at the fold",
        ),
    },
    // ⛔⛔ FILED 2026-09-30 (lane-wallet, DB-273 §19.5 census, the "TO WHOM" question). The row above answers the SUPPLY: the
    // committed minted total moves by exactly weight·rate. It does not answer the REWARD NOTE that the supply move pays
    // out: `apply_yield_claim_attested` records the reward note with no check, the yield mint carrier binds no note
    // commitment, and the stake-spend carrier binds only the principal (out0) and change (out1). So the note may be
    // sealed for ANY value to ANYONE — a relay re-frames the object with its own note — which is inflation (§AT's class),
    // not only a mis-filing. LATENT: no stake note can exist today (the pool refuses the stake format, DB-327/DB-330),
    // so no claim passes the bond-validity carrier. MUST close before staking returns (a decider item, lane-recursion):
    // a reward mint-validity carrier binding the reward cm to the yield carrier's committed amount, with the reward cm
    // under the STAKER's authority. Pin to add then: a relay-swapped reward note mints nothing on a peer.
    // ⭐ ANSWERED 2026-10-02 (DB-365 yield): the reward-follows-principal carrier rides the object, and the yield carrier
    // welds the public yield. The PRODUCER variant (a refused object's notes landing on shape at graft) is the class-wide
    // row below, exactly as for the peg-out change.
    // ⭐ DB-237 (2026-10-02): the reward note is now an OUTPUT of the stake gate itself — its commitment is a public input
    // of the carrier that computes the reward, so neither its value nor its key can be re-framed by a relay.
    Site {
        name: "Class::YieldClaim — the REWARD note",
        authority: Authority::AtTheGraftDoor(
            "the reward note is output 1 of the stake carrier: its commitment is the carrier's public `out1_cm`, so a \
             relay's re-framed note decodes against no statement (`stake_tx::decode` binds the carried notes to the \
             header) and verifies under no carrier",
        ),
        amount: Amount::DerivedByEveryNode(
            "output 1 opens to exactly `(v − w) + r` in-circuit (two range-bound u64 blocks), r the gate's own reward rule; \
             the supply step opens the SAME `reward_commit` — the note credited is the supply minted, never more or less",
        ),
        once: Once::Nullifier(
            "the input note's nullifier is the object's own lane tag (the spent SET) — one input, one reward, on every node",
        ),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::execute_stake` frames it and pools it; `stake_tx::apply_chain_stake` is what \
             every node runs at the fold",
        ),
    },
    // ⛔⛔⛔ FILED 2026-09-30 (DB-365, MEASURED). THE CLASS ROWS AROUND THIS ONE ANSWER AUTHORITY AT APPLY — and the notes an
    // object credits do not wait for that answer. `apply_grafted_block_carry` writes the block's record through
    // `graft_admitted_notes`, which justifies a credit-set object by `chain_object::admissible` (decode only for PegIn,
    // PegOut, YieldClaim, WrappedMint…), and only THEN runs `apply_chain_objects_of`, whose refusal un-justifies nothing.
    // MEASURED in `a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block`:
    // a rogue producer re-sealed its burn block with a peg-out whose change commitment it re-pointed (the v5 tally REFUSES
    // it) and a 10⁹-unit note of its own; D, fed only blocks, RECORDED the note. v5 closed the RELAY variant (a note
    // swapped under the honest header decodes to nothing); the PRODUCER variant is this row.
    // ⭐⭐⭐ CLOSED 2026-10-02 by DB-274 P4b (MEASURED, the same pin, GREEN in 7.2 s): D writes the rogue block's record
    // (`[ingest-record] … 1153 note byte(s)`), folds it, and the fold-time class door refuses the re-pointed peg-out and
    // strips its note (`[objects-fold] ⛔ DB-274 P4b: 1 note(s) of class object(s) refused … left this block's record`);
    // `[db365] … attacker's 1000000000-unit note recorded = false`. The classes NOT decided at the fold (OrderFill,
    // BridgeCredit, AssetMint, AssetSpend, AssetCreate) carry no state-dependent verdict: their whole authority (the
    // composed proof, the open-mint allowance or quorum, the creator signature + opening, conservation) runs in
    // `chain_object::admissible` BEFORE a note is justified.
    Site {
        name: "the notes of a credit-set object its class door refuses",
        authority: Authority::AtTheFold(
            "`Node::objects_decide_at_fold` runs every state-dependent class door (`is_fold_applied_class`: PegIn, PegOut, \
             WrappedMint, YieldClaim, PoolDeposit, PoolWithdraw, Liquidation, PriceMark, WrappedAssetRegister) at the \
             block's canonical fold in the step's pre-state, and `fold_strip_row` removes a refused object's notes from \
             the record; the stateless classes decide in `chain_object::admissible` before justification",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "the credited note is the one the object's class door binds (its carrier's out commitment, the quorum's v5 \
             statement naming the change commitment); a refused door strips it, so no unbound amount survives the fold",
        ),
        once: Once::Nullifier(
            "DB-278: the object's own nullifiers must ride the carrying block's lane (the replay set still answers once)",
        ),
        travels: Travels::AsAChainObject("the credit set the block carries — and that is the door that must decide"),
    },
    // ⭐ LIQUIDATION §10 (2026-10-02) — a pool deposit moves a USDm note's value into the pool and credits a RECEIPT (a claim
    // on the pool) and the change; it creates no value, it re-shapes it, and both notes are bound in-circuit.
    Site {
        name: "Class::PoolDeposit",
        authority: Authority::AtTheGraftDoor(
            "the deposit carrier proves the depositor OWNS the spent USDm note (its key opens the leaf, the nullifier is its \
             own) and the one-step membership carrier proves the note on chain; re-verified at the fold on every node",
        ),
        amount: Amount::DerivedByEveryNode(
            "in-circuit `v = d + change` over range-bound u64 limbs; the receipt opens to `d`, the change to `v − d`, and the \
             pool transition `T + d` opens the SAME `dv = commit(d)` — the pool grows by exactly what the receipt claims",
        ),
        once: Once::Nullifier("the spent note's nullifier is the object's own lane tag; the spent SET refuses a re-use"),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::execute_pool_deposit` frames it and pools it; `pool_tx::apply_chain_pool_deposit` \
             is what every node runs at the fold",
        ),
    },
    // ⭐ LIQUIDATION §10.2 (2026-10-02) — a withdrawal turns a receipt back into USDm: `u` is the withdraw carrier's
    // rounded-down quotient over the pool's REAL (P, S) words, and the pool's T retires by the same `du`.
    Site {
        name: "Class::PoolWithdraw",
        authority: Authority::AtTheGraftDoor(
            "the receipt carrier proves the holder OWNS the receipt (its key, derived from the snapshot the receipt was \
             minted with, opens the leaf) and the one-step membership carrier proves it on chain; re-verified at the fold",
        ),
        amount: Amount::DerivedByEveryNode(
            "the withdraw carrier proves `u·P_dep + r = d·P_now`, 0 ≤ r < P_dep, against the pool's CURRENT words; the \
             credited note opens to the same `du` the transition `T − u` retires — the pool never pays more than it holds",
        ),
        once: Once::Nullifier("the receipt's nullifier is the object's own lane tag; the spent SET refuses a second withdrawal"),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::execute_pool_withdraw` frames it and pools it; `pool_tx::apply_chain_pool_withdraw` \
             is what every node runs at the fold",
        ),
    },
    Site {
        name: "Node::apply_pool_withdraw_at_fold",
        authority: Authority::AtTheGraftDoor(
            "the PSM, the pool epoch, the Fold-door membership, the receipt carrier, the withdraw carrier against THIS node's \
             current pool words, a zero gain, and the transition — all at the fold",
        ),
        amount: Amount::DerivedByEveryNode("the withdraw carrier's quotient; the transition opens the same `du`"),
        once: Once::Nullifier("the object's own lane tag — admitted once at this fold, refused by the spent set after"),
        travels: Travels::AsAChainObject("the APPLY half of `Class::PoolWithdraw`"),
    },
    Site {
        name: "Node::apply_pool_deposit_at_fold",
        authority: Authority::AtTheGraftDoor(
            "the PSM, the pool epoch, the Fold-door membership, the deposit carrier, the snapshot carrier against THIS \
             node's current pool words, and the transition — all at the fold",
        ),
        amount: Amount::DerivedByEveryNode("the deposit carrier's conservation; the transition opens the same `dv`"),
        once: Once::Nullifier("the object's own lane tag — admitted once at this fold, refused by the spent set after"),
        travels: Travels::AsAChainObject("the APPLY half of `Class::PoolDeposit`"),
    },
    Site {
        name: "Node::apply_stake_at_fold",
        authority: Authority::AtTheGraftDoor(
            "the block's epoch, the governance rate, the `MemberDoor::Fold` membership and the stake carrier, all at the fold",
        ),
        amount: Amount::DerivedByEveryNode("the gate's exact reward; `apply_stake_supply` opens the same commitment"),
        once: Once::Nullifier("the object's own lane tag — admitted once at this fold, refused by the spent set after"),
        travels: Travels::AsAChainObject("the APPLY half of `Class::YieldClaim` (the stake object)"),
    },
    Site {
        name: "Class::PegOut",
        authority: Authority::BondedThreshold(
            "peg::peg_out_confidential re-tallies the ≥2/3 attestation over `peg_out_confidential_msg` \
             against THIS node's own bonded set, at graft, on every peer",
        ),
        amount: Amount::DerivedByEveryNode(
            "the redeem-floor carrier proves the reduction against this node's OWN persisted \
             `(reserve_commit, minted_commit)` — a release that would drain past the floor is refused; the CHANGE \
             note is the burn carrier's out1 (conservation), its commitment signed in the v5 statement and required \
             by `peg_out_tx::decode` (DB-365 — before v5 a relay re-framed the change with its own note)",
        ),
        once: Once::Nullifier(
            "the burned note's nullifier retires in each node's own `spent_burns` AND on the chain's \
             nullifier fold — one note, one redeem, on every node",
        ),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::execute_peg_out_burn_verified` frames it and admits it; \
             `peg_out_tx::apply_chain_peg_out` is what every peer runs at graft",
        ),
    },
    Site {
        name: "Node::apply_peg_out_attested",
        authority: Authority::BondedThreshold("the ≥2/3 tally inside `peg::peg_out_confidential`"),
        amount: Amount::DerivedByEveryNode("the redeem-floor carrier against this node's own commitments"),
        once: Once::Nullifier("`spent_burns` plus `record_block_nullifiers` retire the burn here"),
        travels: Travels::AsAChainObject("the APPLY half of `Class::PegOut`"),
    },
    Site {
        name: "Class::PegIn",
        authority: Authority::BondedThreshold(
            "peg::peg_in_confidential re-tallies the ≥2/3 attestation over `peg_in_confidential_msg` \
             against THIS node's own folded validator set, at graft, on every peer",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "`mint_authorized` is bound into the attested message AND the carried mint-validity proof \
             must open the credited note's commitment to exactly it (`verify_mint_validity_bytes`)",
        ),
        once: Once::CommitmentIsTheIdentity(
            "the deposit id retires in each node's own `confidential_deposit_ids` — one deposit, one \
             mint, on every node that grafts the block",
        ),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: `Node::peg_in_confidential` frames it and admits it through \
             `ingest_tx`; `peg_in_tx::apply_chain_peg_in` is what every peer runs at graft",
        ),
    },
    Site {
        name: "Node::apply_peg_in_attested",
        authority: Authority::BondedThreshold(
            "the ≥2/3 tally inside `peg::peg_in_confidential`, run against this node's own bonded set",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "the note's commitment must open to the ATTESTED amount under the carried mint proof, or \
             nothing is credited — the same binding the RPC path runs",
        ),
        once: Once::CommitmentIsTheIdentity("`confidential_deposit_ids` retires the deposit id"),
        travels: Travels::AsAChainObject(
            "the APPLY half of `Class::PegIn` — it runs only on bytes a block carried under that class",
        ),
    },
    Site {
        name: "Node::apply_wrapped_mint_attested",
        authority: Authority::BondedThreshold(
            "the ≥2/3 tally inside `peg::wrapped_mint_confidential`, run against this node's own bonded set",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "DB-80b: the note's commitment must open, IN THE ATTESTED ASSET, to the COMMITTED delta the \
             attested statement carries (`verify_asset_mint_validity_committed_bytes`), or nothing is credited",
        ),
        once: Once::CommitmentIsTheIdentity(
            "`confidential_deposit_ids` retires the (asset, deposit) key — one foreign deposit mints once",
        ),
        travels: Travels::AsAChainObject(
            "the APPLY half of `Class::WrappedMint` (DB-77): it runs only on bytes a block carried under \
             that class — `publish_wrapped_mint` frames and pools the object, `wrapped_mint_tx::\
             apply_chain_wrapped_mint` is what every peer runs at the block's canonical FOLD (DB-274 P4b, \
             `objects_decide_at_fold`). Proven cross-node by \
             `db224_a_wrapped_mint_crosses_the_wire_without_its_payload_and_moves_the_peg_on_a_peer_that_never_pooled_it` \
             (the row cited a pin that existed nowhere until 2026-10-04; the sweep caught it).",
        ),
    },
    Site {
        name: "Node::execute_peg_out_burn_verified",
        authority: Authority::BondedThreshold(
            "the burn-ownership carrier must verify before any reserve moves (no-drain gate)",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "the burn carrier's public inputs bind the burned amount and both output commitments",
        ),
        once: Once::Nullifier("the burn nullifier retires the redeem in peg::spent_burns"),
        travels: Travels::AsAChainObject(
            "⭐ §CS-b CLOSED — it publishes a framed `Class::PegOut` through `ingest_tx` with the burned \
             note's nullifier on the transaction's own lane, and every peer re-runs \
             `peg::peg_out_confidential` at graft (`peg_out_tx::apply_chain_peg_out`). Before this the \
             burn did not travel, so one USDm note redeemed once PER NODE.",
        ),
    },
    Site {
        name: "Node::release_matured_bond",
        authority: Authority::AtTheGossipDoor(
            "unbond_tx::is_authorised — the validator's own ML-DSA signature over its id",
        ),
        amount: Amount::DerivedByEveryNode("the bonded note the block's `bond_set` already carried"),
        once: Once::CommitmentIsTheIdentity("one bonded note, returned once to its owner's bucket"),
        travels: Travels::AsAChainObject(
            "§AS — `Class::Unbond` is the chain object that authorises the release, and the bonded \
             note rides the block's `bond_set`; this function applies what travelled",
        ),
    },
    Site {
        name: "Class::AssetMint",
        authority: Authority::AtTheGossipDoor("asset_tx::AssetMintTx::creator_authorised (§AT, §AX)"),
        amount: Amount::BoundIntoTheAuthority(
            "asset_tx::asset_mint_msg covers asset+amount+note_cm; credit_is_authorised opens the note",
        ),
        once: Once::DeletionTransition(
            "asset_tx::issue_right_cm — the creation plants it, the mint deletes it (§AV)",
        ),
    
        travels: Travels::AsAChainObject("a framed AssetMint transaction every peer re-admits at its own door"),
    },
    Site {
        name: "Class::AssetCreate",
        // Finding A-F34 (2026-11-11): a creation may carry the asset's WHOLE SUPPLY (`asset_tx::CreationSupply`), so this
        // site creates value. The three answers below are for that supply. A creation WITHOUT supply plants the issue
        // right instead (byte-derived from the asset's id; a replayed creation plants the same commitment once); a
        // creation with its supply plants none and retires the right's tag (`AssetCreateTx::carried_notes`).
        authority: Authority::AtTheGossipDoor(
            "chain_object::admissible: the fee burn's carrier (`fee_carrier_verifies`) and, for a creation that carries its \
             supply, the mint's own three questions asked of the mint that supply is (`AssetCreateTx::supply_authorised`: not \
             SAT, the ML-DSA signature of the key the asset's id binds over `asset_mint_msg`, the mint carrier); asked again \
             at the publishing door and at the fold",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "the supply note opens to exactly the amount the creator signed: `credit_is_authorised` verifies the mint carrier \
             against the asset's own tag, and the signed message names the amount and the note's commitment",
        ),
        once: Once::Nullifier(
            "`AssetCreateTx::own_nullifiers`: a creation with its supply retires the asset's issue right, so no mint of the \
             asset can follow; a creation without supply retires the asset's creation id; the fee note's nullifier either way",
        ),
    
        travels: Travels::AsAChainObject("a framed AssetCreate transaction every peer re-admits at its own door"),
    },
    // Audit F15 (2026-11-10) — a paid directory entry: the ONE note it carries is its fee burn's change, the carrier's own
    // out1 (the entry itself carries no note). The class has carried that note since it became a paid object and had no
    // row here; this census stood red on it (found 2026-11-11 by lane goods' own final run, the class being that lane's).
    Site {
        name: "Class::DirEntry",
        authority: Authority::AtTheGossipDoor(
            "chain_object::admissible runs dir_entry_tx::DirEntryTx::self_authorised (the entry's own signature and address binding, the fee carrier); the fold adds the fee note's membership (Node::dir_entry_refusal)",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "dir_entry_tx::dir_burn_cm — the carrier destroys exactly the entry's price (dir_entry_fee_atomic of its bytes) into a cm no key opens and binds the change as out1",
        ),
        once: Once::DeletionTransition(
            "dir_entry_tx::DirEntryTx::own_nullifiers — the fee note's nullifier rides the lane; the spent set refuses a second",
        ),
        travels: Travels::AsAChainObject("a framed DirEntry transaction every peer re-admits at its own door and applies at the fold"),
    },
    // ⭐ §BR-12 L1 (2026-11-01) — a contract deploy: the ONE note it carries is its fee burn's change, the carrier's own out1.
    Site {
        name: "Class::DsolDeploy",
        authority: Authority::AtTheGossipDoor(
            "chain_object::admissible verifies the deployer's signature and dsol_deploy_tx::DsolDeployTx::fee_carrier_verifies; the fold adds the fee note's membership (Node::dsol_deploy_refusal)",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "dsol_deploy_tx::deploy_burn_cm — the carrier destroys exactly the price into a cm no key opens and binds the change as out1",
        ),
        once: Once::DeletionTransition(
            "dsol_deploy_tx::DsolDeployTx::own_nullifiers — the fee note's nullifier and the cid's one-time id ride the lane; the spent set refuses a second",
        ),
        travels: Travels::AsAChainObject("a framed DsolDeploy transaction every peer re-admits at its own door and applies at the fold"),
    },
    // ⭐ §BR-12 L2 (2026-11-01) — a contract call: the publisher's fee note and the caller's change, the fee carrier's two outputs.
    Site {
        name: "Class::DsolCall",
        authority: Authority::AtTheGossipDoor(
            "chain_object::admissible runs dsol_call_tx::DsolCallTx::self_authorised (the caller's signature, the context, the proofs, the fee carrier); the fold adds the fee note's membership, the epoch and the state leaf (Node::dsol_call_refusal)",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "dsol_call_tx::publisher_fee_cm — the carrier binds out0 to the deployed fee at the publisher's public opening and out1 to the change",
        ),
        once: Once::DeletionTransition(
            "dsol_call_tx::DsolCallTx::own_nullifiers — the fee note's nullifier and every Nullifier effect ride the lane; the spent set refuses a second",
        ),
        travels: Travels::AsAChainObject("a framed DsolCall transaction every peer re-admits at its own door and applies at the fold"),
    },
    // ── STILL OPEN, AND FILED ───────────────────────────────────────────────────────────────────────
    Site {
        name: "Class::BridgeCredit",
        // ⭐⭐⭐ CLOSED 2026-09-16 — THE BONDED-THRESHOLD ARM LANDED. It was filed
        // `Authority::Missing("chain_object::admissible decodes, compares the amount to the genesis
        // allowance and returns true — NOTHING asks who may issue a credit … Safe on a value-bearing
        // network ONLY because the allowance is 0 there, which is a fail-closed default and not an
        // authority.")` — and being UNSATISFIABLE was never being AUTHORISED: it also meant the bridge
        // could not credit a real deposit on mainnet at all.
        authority: Authority::BondedThreshold(
            "Node::credit_decide_at_fold (DB-274 P4, 2026-09-30) — the allowance OR a >=2/3 bonded quorum over \
             peg::PegLedger::bridge_credit_msg, tallied by the ONE quorum function (peg::threshold_ok, \
             shared with every peg door) against the FOLDED set in the step's canonical pre-state, so every \
             node reaches one verdict; graft checks the credit's shape only (credit_structurally_attested) and \
             a credit the fold does not attest leaves the block's row before it folds. The message binds \
             deposit id, asset, amount AND note commitment, so an attestation cannot be replayed. admissible \
             stays STRUCTURAL, the same division of labour Class::WrappedMint uses. Four-arm adversarial pin: \
             unattested REFUSED, honestly attested ADMITTED (the calibration), replayed attestation REFUSED, \
             unbonded signer REFUSED.",
        ),
        amount: Amount::BoundIntoTheAuthority("the credit carrier opens the note to the claimed amount"),
        // ⭐ CORRECTED 2026-09-14 (read at the apply, not off another register): `apply_chain_bridge_credit`
        // answers `AlreadyHeld` when the record already holds the note's commitment, on every node — so
        // the SAME credit cannot land twice. What it does not key on is `deposit_id`: a second credit for
        // the same foreign deposit under a NEW note is a different commitment. That is the bonded
        // attestation arm's job (the PSM path keys `confidential_deposit_ids`), the same arm AUTHORITY
        // above is waiting on — one gap, filed once.
        once: Once::CommitmentIsTheIdentity(
            "bridge_credit_tx::reconcile_attested_credit (run at the credit's fold) — AlreadyHeld on a held \
             commitment, every node",
        ),
    
        travels: Travels::AsAChainObject(
            "a framed BridgeCredit transaction, justified to peers by the block's own §BA `credit_set`",
        ),
    },
    // ── THE PRODUCER — the site the census was missing, and the largest one ──────────────────────────
    // ⛔ DB-223 (2026-09-27): this site is closed for what its three sources JUSTIFY AS PRESENT — a verified spend
    // statement, a carried object, a bond return. It does NOT answer whether an ORDINARY spend's INPUT existed: the
    // note transition proves validity only, so that arm is filed as its own OPEN site directly below.
    Site {
        name: "Block::output_notes",
        // ⭐⭐⭐ §BA CLOSED 2026-09-15 — MEASURED ON THE PEER, BOTH ARMS:
        //   [§BA]      peer RECORDED it=false · peer holds it UNSPENT=false   (was true · true)
        //   [§BA-lane] JUSTIFIED credit unspent=true · PLANTED note unspent=false, SAME block, peer
        //              holding NO transaction body — the half that proves the door did not merely
        //              learn to say no, which is exactly how §BO refuted the four earlier closes.
        authority: Authority::AtTheGraftDoor(
            "THREE sources, each checked by the peer against something it holds or can verify, and a \
             note with none of them is REFUSED (`Node::graft_admitted_notes`; there is no \
             unjudged-implies-received arm left). (1) THE NOTE TRANSITION — every tuple is the public \
             statement of a spend carrier that VERIFIED IN CIRCUIT, and the peer recomputes the digest \
             from the block's own list before verifying, so the list is pinned by the proof. (2) THE \
             CREDIT SET (`Block::credit_set`, header-bound by `credit_set_root`) — for the notes no \
             spend publishes, the block CARRIES the framed chain object and the peer re-runs \
             `chain_object::admissible` plus `carried_note_payloads` on those bytes itself. (3) THE \
             BOND-RETURN SOURCE — the one object that declares no note by design, checked against the \
             `out0` bytes this node itself holds as bonded. ⛔ §BO's liveness objection was MEASURED \
             FALSE rather than argued away: there is no coinbase note at all — `output_notes` is 0 \
             bytes on an idle block AND 0 with a pooled transaction, the coinbase being \
             `header.miner_commitment`, which the PoW binds.",
        ),
        amount: Amount::DerivedByEveryNode(
            "the amount lives in the note, and the note is now only admitted when a proof or a carried \
             object justifies it — so the planter no longer chooses the opening, the justifier does",
        ),
        once: Once::CommitmentIsTheIdentity(
            "one commitment is credited once — and it now BINDS, because a commitment nothing justifies \
             never enters the set in the first place",
        ),
    
        travels: Travels::AsAChainObject("it IS the block's carried notes — the header binds `output_notes_root`"),
    },
    // ⛔⛔⛔ DB-223 — OPEN. MEASURED by `node::tests::a_peer_does_not_credit_the_outputs_of_a_spend_whose_input_never_existed`
    // (RED in every sweep of 2026-09-26/27): a producer pools a spend of a note NOBODY was ever paid, past its own
    // submit door, and lays the block; a peer fed only the block records its 999,999,000-unit output.
    Site {
        name: "Block::output_notes via an ordinary spend",
        // ⭐⭐⭐ DB-223 Q7 CLOSED THE AUTHORITY HALF (2026-10-02, MEASURED — `node::tests::a_peer_does_not_credit_the_outputs_of_
        // a_spend_whose_input_never_existed` GREEN, both arms: a stated spend with its member proof stripped is not credited,
        // and a forged member proof at an invented anchor is refused at the fold — `[spend-fold] ⛔ DB-223: 1 stated spend(s)
        // … refused at their fold; 2 note(s) left this block's record`). Before: RED on main, the peer recorded the
        // fabricated 999,999,000-unit output. The honest calibration is `mesh_runtime_scenarios::tests::a_payment_one_party_
        // lays_is_recorded_by_its_peer_over_the_hub` (a funded spend with its member leg, recorded by the peer).
        authority: Authority::AtTheFold(
            "`member_transition::spends_proven_with_members` — a stated spend counts only when the block's member \
             transition covers it, cross-bound (ingest refuses the block; `graft_admitted_notes` and `lane_justified` \
             justify nothing without it), and `Node::member_anchors_at_fold` judges each input's ANCHOR against the \
             canonical ring at the fold (a refused spend's outputs leave the row and its tags retire nothing)",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "note_transition::verify — conservation value_in = out0 + out1 + fee is proven in circuit per tuple",
        ),
        // ⛔⛔⛔ DB-358 (2026-09-28) — this answer read `Once::Nullifier("nf_sparse — the block's nullifier_proof proves
        // each spend's nullifier NEW …")`, and that was FALSE. MEASURED by
        // `node::tests::a_peer_refuses_a_second_spend_of_one_nullifier_carried_in_a_later_block` (RED): a producer lays a
        // SECOND spend of one nullifier in a later block and the peer, fed only the blocks, records its output.
        // Since 2026-09-28 the canonical record fold refuses the re-spend (first spender in canonical order counts,
        // `respend_decide_at_fold`; the pin above is GREEN), a restart keeps the first-contact memo (increment 2), and the
        // send door admits only a FOLDED record (DB-358 (1)). What keeps this `Missing` is named below; it is not rounded
        // up to an answer.
        // ⭐ CLOSED 2026-10-04 (MEASURED). DB-353 §13.6 made the decision read the canonical FOLD-POINT set `S_b` (the held
        // view ∪ every step noted before `b`), never an arrival fact; what remained was the fixtures. Residual 3:
        // `db358_r3_a_bundle_joiner_does_not_credit_a_re_spend_carried_in_its_window_and_keeps_folding` GREEN once the
        // joiner warms its view and the band relays ("A false C false": the joiner refuses the carried re-spend and keeps
        // folding; its control credits the honest spend on both). Residual 4 (a reorg past the fold lag):
        // `db358_r4_a_fill_race_met_after_both_producers_folded_pays_the_same_taker_on_both_parties` GREEN.
        once: Once::Nullifier(
            "`respend_decide_at_fold` — the first spender of a nullifier in CANONICAL fold order counts; every later one \
             loses its outputs, decided from the fold-point set S_b (DB-353 §13.6) on every node, a joiner's carried \
             window and a reorg past the fold lag included: db358_r3_a_bundle_joiner_does_not_credit_a_re_spend_carried_\
             in_its_window_and_keeps_folding (+ its control) and \
             db358_r4_a_fill_race_met_after_both_producers_folded_pays_the_same_taker_on_both_parties",
        ),
        // ⭐ DB-351 CLOSED 2026-09-28 (user: "address 351"). The note's FILING data (the locator clues a seed-only restore
        // finds it by) sat outside the tx id and the proof, so a relay could race a stripped copy that settled UNFILED.
        // Now each spend and multi-spend carrier binds D = H(outputs' (cm, k)) LAST (decider, lane-recursion); the pool door
        // recomputes D from the tx's own canonical clue list (`Node::tx_filing_d`, NON_CANONICAL_CLUES by name) and every
        // peer recomputes it from the block's header-bound `oli_tags` (`note_transition::verify`). account_targets stay
        // unbound, and they are not the restore path: the note is always found by its bound OLI filing.
        travels: Travels::AsAChainObject(
            "PqTx + the block's note transition, whose per-spend D binds the filed (cm, k): \
             note_transition::db351_a_transition_verifies_only_under_the_filing_its_spends_bound (strip/rewrite/add/dup \
             refused on the peer) + wallet pq_spend::db351_the_wallets_filing_digest_is_the_nodes_and_a_moved_clue_list_\
             verifies_nowhere (wallet D == pool-door D)",
        ),
    },
    Site {
        name: "Class::WrappedMint",
        authority: Authority::BondedThreshold("peg::PegLedger — the ≥2/3 tally at apply (threshold_ok)"),
        amount: Amount::DerivedByEveryNode("the registered wrapped-asset ratio, itself a chain object"),
        // ⭐ CORRECTED 2026-09-14: this was filed `Once::Missing` on the strength of the e2e register alone.
        // Read at the ledger: `wrapped_mint_confidential` keys every mint by `wrapped_deposit_key(asset,
        // deposit_id)` and answers `PegOutcome::Replay` on a second one — applied at the graft seam on
        // every node, pinned twice. A census entry must be read off the code, not off another register.
        once: Once::CommitmentIsTheIdentity(
            "peg::wrapped_deposit_key — one foreign deposit mints once (PegOutcome::Replay), on every node",
        ),
    
        travels: Travels::AsAChainObject("a framed WrappedMint transaction carrying its peg transition"),
    },
    Site {
        name: "Class::OrderFill",
        authority: Authority::AtTheGossipDoor("whir_rec_block::verify_order_fill over the terms"),
        amount: Amount::BoundIntoTheAuthority("the fill carrier's public bind names both payouts"),
        once: Once::Nullifier("the fill's input nullifiers ride the padded lane"),
    
        travels: Travels::AsAChainObject("§AK put the fill on the transaction path — `execute_order_fill` reaches `ingest_tx`"),
    },
    Site {
        name: "Class::AssetSpend",
        // ⭐ DB-223 Q7 (2026-10-02, MEASURED — `asset_tx::tests::a_peer_does_not_credit_an_asset_transfer_whose_input_never_
        // existed`): the membership half ran at GRAFT after the outputs were recorded, so a refusal stripped nothing. It is
        // now decided at the fold (`is_fold_applied_class`), and a refused transfer's outputs leave the row
        // (`[objects-fold] ⛔ DB-274 P4b: 2 note(s) … refused … left this block's record`).
        authority: Authority::AtTheFold(
            "asset_tx::asset_spend_refusal at the canonical fold (`Node::objects_decide_at_fold`): conservation in one asset \
             and the note-membership carrier against this node's own record roots; a refused transfer's notes are stripped",
        ),
        amount: Amount::BoundIntoTheAuthority("conservation over the output commitments it carries"),
        once: Once::DeletionTransition("the spent note leaves the unspent tree (§AQ)"),
    
        travels: Travels::AsAChainObject("a framed AssetSpend transaction carrying its burns and outputs"),
    },
    // ⭐ SATOSHI (DB-393 B4) — the ONE issuance route of SAT: each produced block's mining reward. Filed 2026-10-23 (lane a,
    // G7): the class carried a note since the native token landed and was in no census.
    Site {
        name: "Class::SatoshiReward",
        authority: Authority::AtTheFold(
            "Node::apply_sat_reward_at_fold at the carrying block's canonical fold: the reward must state the carrying \
             block's OWN parent key and be the block's FIRST reward; `chain_object::admissible` refuses the blob before \
             justification unless its decode matches the schedule and its carrier opens; carried only in the earning \
             block's credit set, never pooled or relayed (absent from `wrapper_binds_object`)",
        ),
        amount: Amount::DerivedByEveryNode(
            "satoshi::SatoshiRewardTx::credit_is_authorised — the asset-mint carrier opens the note to exactly the schedule's \
             public amount for its key, re-verified at the fold; `Peg::credit_sat_reward` refuses any credit past the \
             21,000,000 SAT hard cap, and the objects journal rewinds the issued total on a re-fold",
        ),
        once: Once::Nullifier(
            "satoshi::reward_nf — one reward per note commitment enters the spent SET, so a copied reward is refused; the \
             fold's `sat_seen` admits one reward per block and the key binds it to that block",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: laid FIRST in the producing block's credit set, travelling whole"),
    },
    // ⭐ §BR-3 17.3 (2026-10-29) — the delegated-SAT conversion: SAT ↔ delegated ↔ unbonding, each step burning exactly what
    // it mints. It creates no value; filed the day the class landed.
    Site {
        name: "Class::SatDelegation",
        authority: Authority::AtTheFold(
            "sat_delegation_tx::apply_chain_sat_delegation at the carrying block's canonical fold: the input's membership \
             (Fold door), the seat rule (a live unslashed seat of the named instance), the unbonding window, the maturity; \
             `chain_object::admissible` verifies both carriers before justification",
        ),
        amount: Amount::DerivedByEveryNode(
            "SatDelegationTx::carriers_verify: the asset bond-validity carrier burns exactly `amount` of the input tag into an \
             output bound to the minted note, and the asset mint carrier opens the minted note to exactly `amount` of the \
             output tag — conservation across the conversion, by the two carriers",
        ),
        once: Once::Nullifier(
            "the burned input's nullifier is the object's own lane tag (`object_own_nullifiers`), refused by the spent SET",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled, laid in the credit set, applied at the fold on every node"),
    },
    // ⭐ §BR-3 17.5 layer 1 (2026-10-29) — the repayment pot sold at the floor: the buyer burns USDm, the pot's slashed SAT
    // (already issued) moves to the buyer's note. It brings no SAT into existence (SAT's three doors are unchanged) and retires
    // the USDm it burns. Filed with the census fix the day its family run found it missing.
    Site {
        name: "Class::PotFill",
        authority: Authority::AtTheFold(
            "Node::pot_fill at the carrying block's canonical fold: the buyer's membership (Fold door), ≥ 2/3 of the bonded \
             custody weight over `PegLedger::pot_fill_msg` (the request digest and both supply commitments), the retire leg, \
             the pot and the floor; `chain_object::admissible` verifies both carriers before justification",
        ),
        amount: Amount::DerivedByEveryNode(
            "PotFillTx::carriers_verify: the bond-validity carrier burns exactly `burn_usdm` into the output bound to the SAT \
             note, the SAT note opens to exactly `sat_out` of SAT's tag; the door refuses `sat_out × floor > burn × PRICE_SCALE` \
             and `sat_out` above the pot",
        ),
        once: Once::Nullifier(
            "the burned input's nullifier is the object's own lane tag (`object_own_nullifiers`), refused by the spent SET",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled with its two notes, applied at the fold on every node"),
    },
    // ⭐ §BR-15 §18.8 (2026-11-02) — a sealed DeFi order: the owner burns a USDm note into the pool (its amount a commitment);
    // the only note it carries is the burn's change (conserving: the input less the burned order amount and the fee).
    Site {
        name: "Class::DefiOrder",
        authority: Authority::AtTheFold(
            "defi_batch::apply_chain_defi at the carrying block's canonical fold: the burned note's member leg (Fold door), the \
             order's share proof against the book's roster (`order_share_r1cs`), the open batch; `chain_object::admissible` \
             verifies the burn carrier before justification",
        ),
        amount: Amount::DerivedByEveryNode(
            "verify_burn_validity_committed_bytes: the spend conserves (input = burned order amount + change + the protocol \
             fee) and the burned amount is exactly the committed `amount_commit` every share proof and claim opens",
        ),
        once: Once::Nullifier("the burned note's nullifier is the object's own lane tag (`object_own_nullifiers`), refused by the spent SET"),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled with its change note, applied at the fold on every node"),
    },
    // ⭐ §BR-15 §18.8 (2026-11-02) — a DeFi claim (or refund): mints the bought SAT (or the refunded USDm) for exactly its order's
    // fill at its batch's tick, against a claim leaf a verified settlement (or expiry) inserted into the note set.
    Site {
        name: "Class::DefiClaim",
        authority: Authority::AtTheFold(
            "defi_batch::apply_chain_defi at the carrying block's canonical fold: the claim leaf's member leg (Fold door) — the \
             leaf exists only because a settlement whose every custodian audit verified (or an expiry of the open batch) \
             inserted it; `chain_object::admissible` verifies the claim relation and the mint first",
        ),
        amount: Amount::DerivedByEveryNode(
            "claim_circuit: 0 ≤ a·p_num − out·p_den < p_den for the order's committed amount and the leaf's price (exactly \
             ⌊a·p⌋; (1, 1) for a refund), and verify_asset_mint_validity_committed_bytes opens the note to exactly `out`",
        ),
        once: Once::Nullifier(
            "the claim nullifier P(a_blind, CLAIM_NF_DOMAIN) — ONE per order, shared by its claim and its refund — is the \
             object's own lane tag, refused by the spent SET",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled with its note, applied at the fold on every node"),
    },
    // ⭐ §BR-4 B4-2 (2026-10-29) — a debt unit opened: a peg-in whose mint is backed by its OWN deposit at 110 % of the unit's band
    // floor, plus the unit note (a debt marker of `U` under the unit's tag, not money).
    Site {
        name: "Class::UnitOpen",
        authority: Authority::BondedThreshold(
            "unit_open_tx::apply_chain_unit_open runs the peg-in's own apply (`Node::apply_peg_in_attested`): ≥ 2/3 of the bonded \
             weight over `peg_in_confidential_msg`, whose deposit id is `unit_open_tx::unit_deposit_id` (binding the unit's terms \
             and note), re-tallied at the fold on every node",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "the peg-in carrier proves the unit's own deposit backs `U` at `PegLedger::mint_backing` (110 % of the band floor, \
             DB-470); the mint carrier opens the USDm note to the committed delta; `UnitOpenTx::unit_carrier_verifies` opens the \
             unit note to exactly `U` of `UnitTerms::tag`",
        ),
        once: Once::CommitmentIsTheIdentity(
            "the unit's deposit id AND its base Bitcoin deposit's id retire as one-time ids (`object_own_nullifiers`) and in \
             `confidential_deposit_ids`: one deposit, one unit",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled with its two notes, applied at the fold on every node"),
    },
    // ⭐ §BR-4 B4-3 (2026-10-29) — a debt unit closed: the unit note and the debt die; the only note it carries is the debt burn's
    // change (conserving: the burn's input less the burned debt).
    Site {
        name: "Class::UnitClose",
        authority: Authority::AtTheFold(
            "Node::unit_close at the carrying block's canonical fold: both burns' memberships (Fold door), then \
             `PegLedger::unit_close_door` — the day's exact debt (`UnitBook::close_terms`), ≥ 2/3 of the bonded custody weight \
             over `PegLedger::unit_close_msg`, the retire and release legs against this node's own commitments",
        ),
        amount: Amount::DerivedByEveryNode(
            "UnitCloseTx::carriers_verify: the asset bond destroys exactly `U` of the unit's tag with zero change, the \
             bond-validity burn destroys exactly `debt_atomic` and its change is out1; the supply falls by `U`, the reserve by \
             `collateral_sats`, the interest moves into the stakers' pool",
        ),
        once: Once::Nullifier(
            "both burns' nullifiers are the object's own lane tags (`object_own_nullifiers`), refused by the spent SET",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled with its change note, applied at the fold on every node"),
    },
    // ⭐ §BR-13 (2026-10-29) — the developer SAT set-aside: SAT's second door. One canonical object compiled into every node,
    // applied once, its note proven at most 2M SAT over a public input. Filed the day the class landed.
    Site {
        name: "Class::SatSetAside",
        authority: Authority::AtTheFold(
            "sat_set_aside::apply_chain_set_aside at the carrying block's canonical fold: the object's bytes equal the \
             network's canonical bytes compiled into every node; `chain_object::admissible` checks the same before justification",
        ),
        amount: Amount::DerivedByEveryNode(
            "SatSetAsideTx::proves_the_bound: the asset spend carrier verifies over a PUBLIC input of exactly \
             SAT_SET_ASIDE_MAX SAT (its leaf recomputed from the published opening and blind), so the recorded output holds \
             at most 2M SAT and the unrecorded output can never be spent",
        ),
        once: Once::Nullifier(
            "the peg ledger's `set_aside_applied` flag, and `set_aside_nf()` as the object's own lane tag refused by the spent SET",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled by any producer, laid in the credit set, applied at the fold on every node"),
    },
    // ⭐ §BR-3 17.6 (2026-10-29) — a validator's own-weight bonders' yield: fee USDm already in the bonders' pool reaches the
    // validator whose own weight earned it. It creates no value; filed the day the class landed.
    Site {
        name: "Class::BountyPayout",
        authority: Authority::AtTheFold(
            "bounty_payout_tx::apply_chain_bounty_payout at the carrying block's canonical fold: ≥ 2/3 of the bonded custody \
             weight's ML-DSA-65 signatures over (nonce, amount, note commitment, clue digest), the constitutional cap (10 % of \
             the surplus buffer), the buffer's cover; `chain_object::admissible` verifies the signatures and carrier first",
        ),
        amount: Amount::DerivedByEveryNode(
            "the signed amount, paid only from the surplus buffer (the supply does not move); the mint carrier opens the note \
             to exactly that",
        ),
        once: Once::Nullifier("`bounty_nf(nonce)` is the object's own lane tag, refused by the spent SET"),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled, laid in the credit set, applied at the fold on every node"),
    },
    Site {
        name: "Class::BondYieldClaim",
        authority: Authority::AtTheFold(
            "bond_yield_claim_tx::apply_chain_bond_yield_claim at the carrying block's canonical fold: the id's ML-DSA-65 \
             signature (`pubkey_id(pubkey) == vid`), the index this fold holds, the amount owed, the pool's cover; \
             `chain_object::admissible` verifies the key, signature and carrier before justification",
        ),
        amount: Amount::DerivedByEveryNode(
            "ValidatorSet::own_yield_at(vid, Y): the own weight × the index rise since the seat last settled, plus its \
             accrual — computed by every node from its own state; the mint carrier opens the note to exactly that",
        ),
        once: Once::Nullifier(
            "`claim_nf(vid, index)` is the object's own lane tag, refused by the spent SET; the accrual is zeroed in the step",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: pooled, laid in the credit set, applied at the fold on every node"),
    },
    // ⭐ §BR-11 (2026-10-28) — the miner pool's per-block payout: fee USDm already in the pool reaches a block producer. It
    // creates no value (the pool falls by exactly what the note holds); filed the day the class landed.
    Site {
        name: "Class::MinerPayout",
        authority: Authority::AtTheFold(
            "Node::apply_miner_payout_at_fold at the carrying block's canonical fold: the payout must state the carrying \
             block's OWN parent key and be the block's FIRST payout; `chain_object::admissible` refuses the blob before \
             justification unless it decodes and its note opens to its stated amount; carried only in the producing \
             block's credit set, never pooled or relayed",
        ),
        amount: Amount::DerivedByEveryNode(
            "miner_payout_tx::MinerPayoutTx::credit_is_authorised recomputes cm = asset_note_cm(amount, USDm, opening); \
             `PegLedger::pay_miner_payout` pays only the open quarter's rate (`miner_rate` of the closed quarter's accrual \
             over its folded blocks, Kani `miner_rate_never_overdraws`) and only from what the miner pool holds — the pool \
             falls by exactly the amount, so no unit is minted; the objects journal rewinds it on a re-fold",
        ),
        once: Once::Nullifier(
            "miner_payout_tx::payout_nf — one payout per note commitment enters the spent SET, so a copied payout is refused; \
             the fold's `payout_seen` admits one payout per block and the key binds it to that block",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: laid right after the reward in the producing block's credit set, travelling whole"),
    },
    // ⭐ SATOSHI §6 — a SAT custody bond creates no value: it re-shapes one spent SAT note into a locked custody weight and a
    // credited change note (the class carries the CHANGE note). Filed 2026-10-23 (lane a, G7) with the reward above.
    Site {
        name: "Class::SatBond",
        authority: Authority::AtTheFold(
            "sat_bond_tx::sat_bond_refusal at the fold (`Node::objects_decide_at_fold`): signed by the key it seats, the \
             welded carrier, the bonded note's one-step membership against this node's own record roots, unspent in the \
             fold-point SET, and the seat rule (`admit_refusal` / `rebond_refusal`); a refused bond's change note is stripped",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "SatBondTx::weld_is_authorised — the carrier locks exactly the stated weight in SAT (asset-tagged) and binds the \
             change commitment to the spent note's value minus that weight; a re-bond must RAISE the weight (§9.3 R1), so \
             the change comes only from the fresh note",
        ),
        once: Once::Nullifier(
            "SatBondTx::own_nullifiers — the bonded note's nullifier (and a re-bond's locked note's) ride the carrying \
             block's lane; the spent SET refuses a re-use, and a stranger-signed copy owns no nullifier (§9.3 R3)",
        ),
        travels: Travels::AsAChainObject(
            "IT IS the chain object: pooled by the validator, carried in the credit set, seated from the block by `seat_sat_bond`",
        ),
    },
    // ⭐ IonSwap pools (2026-11-11) — an ORDER creates no value: each leg destroys a public amount of one asset into the
    // order's own burn and returns the rest as change (the notes the class carries are those change notes).
    Site {
        name: "Class::IonOrder",
        authority: Authority::AtTheFold(
            "node::objects::ion_pool::apply_chain_ion at the carrying block's canonical fold (`Node::ion_order_refusal`): every \
             leg's welded spend (`IonOrderTx::legs_verify`, which `chain_object::admissible` runs first) and its note's \
             one-step membership against this node's own record roots (Fold door); a refused order's change notes are stripped",
        ),
        amount: Amount::BoundIntoTheAuthority(
            "each leg's carrier burns exactly the order's stated amount of that asset into the order's own burn commitment \
             (`ion_burn_cm` under `ion_order_bind`, so a leg proven for one order verifies in no other) and binds the change \
             commitment to the spent note's value less that amount (a USDm leg: less the protocol fee too)",
        ),
        once: Once::Nullifier("the legs' nullifiers are the object's own lane tags (`IonOrderTx::own_nullifiers`), refused by the spent SET"),
        // THE ROUTES of this class, named so the coverage guard and a reader find them here: `/submit_ion_order` is the
        // one door a wallet reaches the class through (it parses the order and calls `Node::publish_ion_order`, which
        // pools the framed object after the fold's own verdict at the Admit door; nothing is written to the ledger by
        // the route). `/ion/pools` and `/ion/pool` only READ this node's own copy of the pools' rows. Pinned on two
        // nodes by `a_pool_is_opened_traded_and_left_by_its_provider_on_two_nodes`, through a rogue producer by
        // `ion_rogue_false_pool_objects_carried_by_a_rogue_producer_move_nothing_on_the_peer_and_the_true_ones_then_land`,
        // and on real nodes by `scratchpad/net/pool.py`.
        travels: Travels::AsAChainObject("IT IS the chain object: published at `/submit_ion_order`, pooled with its change notes, joined to the ledger's pending list at the fold on every node"),
    },
    // ⭐ IonSwap pools (2026-11-11) — a SETTLEMENT pays a batch: its payout notes are what the pool's pending orders burned,
    // priced by the pool's own row. It has no proof of its own because it has nothing of its own: every word is recomputed.
    Site {
        name: "Class::IonSettle",
        authority: Authority::AtTheFold(
            "IonSettleTx::verdict at the carrying block's canonical fold: the row it starts from is proven under the ledger's \
             own contract-state root (`contract_state::verify_path`), the batch is RECOMPUTED from the ledger's own pending \
             orders, and every carried payout note must be byte for byte the recomputed one; then the layer word \
             (`PegLedger::ion_apply_settlement`) refuses a batch that takes more USDm out than the pools layer holds",
        ),
        amount: Amount::DerivedByEveryNode(
            "ion_pool_tx::settle — the pool's constant-product arithmetic over its row and the amounts its pending orders \
             burned, with both assets' conservation checked inside; the creator of the object chooses no number",
        ),
        once: Once::Nullifier(
            "IonSettleTx::own_nullifiers (the one-time id of the settlement's own bytes) rides the lane; and a second settlement \
             of a batch proves a row that is no longer the pool's leaf (a row's batch number only rises) for orders that have \
             left the pending list",
        ),
        travels: Travels::AsAChainObject("IT IS the chain object: formed by any node, pooled with its payout notes, recomputed at the fold on every node"),
    },
];

/// ⛔ THE SITES THAT DO NOT YET ANSWER ALL THREE. This list may only ever SHRINK.
///
/// A site here is a KNOWN, NAMED hole with its reason in `SITES`. A site NOT here that fails the standard
/// is a hole nobody wrote down — which is exactly what §AT, §AV and §AX each were on the morning they were
/// found.
/// ⭐ EMPTY AS OF 2026-09-16 — `Class::BridgeCredit` left when its bonded-threshold arm landed (see its
/// `Site` above). ⛔ An empty list is not a licence to stop looking: `every_value_creating_site_answers_
/// authority_amount_and_once` is what keeps it empty, and a NEW site with an unanswered question fails
/// that test rather than landing here quietly.
/// ⭐⭐⭐ THE FUNCTIONS THAT BRING A NOTE INTO LOCAL EXISTENCE — derived from `node.rs`, over the ONE
/// primitive that does it.
///
/// ⛔⛔⛔ THIS UNIVERSE IS THE POINT. The census's other completeness rule derives from `Class::` variants
/// in `chain_object.rs`, so a value-creating RPC HANDLER is invisible to it — which is how
/// `Node::peg_in_confidential`, the BTC/XMR deposit route that is the primary way USDm is issued, sat
/// outside every census and therefore off every list of what was left. `record_note_payload` is the single
/// call that puts a note into this node's state, so its CALLERS are the honest universe: handlers and
/// classes alike, and a mint path added tomorrow lands here without anyone remembering to add it.
///
/// `_for_test` fixtures are excluded by name — they mint into a test node, never into a user's balance.
#[must_use]
/// ⭐⭐⭐ DB-195 — THE CENSUS MUST NOT COUNT A **TEST** AS A PRODUCTION MINTING SITE.
///
/// `local_note_minting_fns` finds every function in `node.rs` whose body calls `record_note_payload(`.
/// `node.rs` also contains `#[cfg(test)] mod` blocks whose functions sit at the SAME indent as `impl
/// Node` methods and legitimately call that primitive to build fixtures — so a new TEST fails the
/// completeness rule as though it were an unfiled mint path.
///
/// ⛔ MEASURED 2026-09-25: DB-165's pin
/// `a_produced_block_carries_a_constant_width_note_carrier_and_tampering_is_refused` was reported as
/// *"A FUNCTION MINTS A NOTE AND IS IN NO CENSUS"*. Adding a test to `SITES` to silence that would make
/// the census meaningless, and relaxing the rule would restore exactly the blindness it was built
/// after (`Node::peg_in_confidential` — the way USDm is actually issued — sat outside every census).
///
/// ⭐ SO THE UNIVERSE IS NARROWED TO PRODUCTION CODE, WHICH IS WHAT THE RULE ALWAYS MEANT. Test modules
/// in this tree are declared `#[cfg(test)]` immediately followed by `mod <name> {` at COLUMN 0 and close
/// at `}` at column 0; those spans are cut before scanning. Nothing about the rule itself moves: every
/// production caller of the primitive must still answer AUTHORITY / AMOUNT / ONCE / TRAVELS, and
/// `strip_cfg_test_modules_finds_the_spans` pins that the cut lands where it is meant to.
pub(crate) fn strip_cfg_test_modules(src: &str) -> String {
    // ⛔ THE VISIBILITY MATTERS. `node.rs` declares its main test module `#[cfg(test)]\npub(crate) mod
    // tests {`; a first cut matched only bare `mod ` and stripped nothing, so the false positive stood.
    const OPENERS: [&str; 3] = ["mod ", "pub mod ", "pub(crate) mod "];
    // ⛔ THE TEST FAMILIES (lane a 2026-10-23, G7): since the pins split per feature, a test module is also
    // `#[cfg(all(test, feature = "pins-node"))]` and may carry more attributes (`#[allow(unused_imports)]`) before
    // `mod`. A cut that knew only `#[cfg(test)]\nmod` read every `node::pins` fixture as a production minting function
    // (MEASURED: `a_produced_block_carries_a_constant_width_note_carrier…`, `db276_…` named in no census).
    let is_test_cfg = |line: &str| line == "#[cfg(test)]" || line.starts_with("#[cfg(all(test, feature = \"pins-");
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    loop {
        let Some(at) = rest.find("\n#[cfg(") else {
            out.push_str(rest);
            return out;
        };
        let after = &rest[at + 1..];
        let line = after.split('\n').next().unwrap_or("");
        let mut body = &after[line.len().min(after.len())..];
        body = body.strip_prefix('\n').unwrap_or(body);
        // further attributes between the cfg and the module (`#[allow(…)]`) belong to the same item
        while body.starts_with("#[") {
            let l = body.split('\n').next().unwrap_or("");
            body = body[l.len()..].strip_prefix('\n').unwrap_or(&body[l.len()..]);
        }
        if !is_test_cfg(line) || !OPENERS.iter().any(|o| body.starts_with(o)) {
            // `#[cfg(test)]` on something that is not a module (a lone fn, a const), or a non-test cfg: keep scanning
            // past it rather than cutting, so production code is never dropped by accident.
            out.push_str(&rest[..at + 1]);
            rest = &rest[at + 1..];
            continue;
        }
        out.push_str(&rest[..at]);
        // The module closes at the first `}` that starts a line at column 0.
        match body.find("\n}\n") {
            Some(end) => rest = &body[end + 3..],
            None => return out, // unterminated: the rest of the file is that module
        }
    }
}

/// Moved to `crate::test_census` (always compiled for tests): production `#[cfg(test)]` census pins read it with the harness off.
pub use crate::test_census::node_production_source;

/// ⭐⭐⭐ DB-196 — THE UNIVERSE CHECK IS A FUNCTION, SO THE READINESS REPORT CAN ASK IT.
///
/// ⛔ THE HOLE THIS CLOSES, MEASURED 2026-09-25. `harness::readiness::live_criteria` computes
/// *"value-creation sites not fully answered"* from `SITES` alone, so it read **0 open = ✅** while
/// `every_local_note_minting_function_is_in_the_census` was FAILING (DB-195: the scanner counted a
/// `#[cfg(test)]` fixture as a production mint path). A criterion backed by a census is only as good as
/// that census still COVERING ITS UNIVERSE, and nothing connected the two.
///
/// Returning the gaps rather than asserting them lets BOTH callers use the same answer: the test
/// asserts it is empty, and the readiness report counts each entry as an open site. A census that stops
/// covering its universe now makes the criterion red by construction instead of quietly staying green.
///
/// Each entry is a SENTENCE naming what is uncovered, because this text is what a reader sees in the
/// readiness report's blocker line.
#[must_use]
pub fn census_universe_gaps() -> Vec<String> {
    let mut gaps = Vec::new();
    let Some(node_src) = node_production_source() else {
        // ⛔ NOT SILENCE. A universe that cannot be read is a universe that cannot be checked, and the
        // whole point of this function is that an uncheckable census must not read as a clean one.
        gaps.push(
            "the node source could not be read, so the minting-function universe is UNCHECKED — the              census cannot be known to cover it"
                .to_string(),
        );
        return gaps;
    };
    let named: BTreeSet<String> = SITES
        .iter()
        .filter_map(|s| s.name.strip_prefix("Node::").map(str::to_string))
        .collect();
    let minters = local_note_minting_fns(&node_src);
    if minters.len() < 3 {
        gaps.push(format!(
            "the minting-function reader found only {} function(s) — a derivation that finds nothing is              green and worthless, so the census's universe is not established",
            minters.len()
        ));
    }
    for m in minters.difference(&named) {
        gaps.push(format!(
            "`Node::{m}` mints a note and is in NO census — it brings value into existence, so it must              answer AUTHORITY / AMOUNT / ONCE / TRAVELS"
        ));
    }
    gaps
}

pub fn local_note_minting_fns(src: &str) -> BTreeSet<String> {
    // DB-195: production code only — a `#[cfg(test)]` module's fixtures are not mint paths.
    let src = &strip_cfg_test_modules(src);
    // Function boundaries at one indent level inside `impl Node` — the same shape every method in
    // `node.rs` has. A body runs from its own `fn` to the next one.
    let mut starts: Vec<(usize, String)> = Vec::new();
    for (idx, _) in src.match_indices("\n    ") {
        let rest = &src[idx + 5..];
        let after_vis = rest
            .strip_prefix("pub fn ")
            .or_else(|| rest.strip_prefix("pub(crate) fn "))
            .or_else(|| rest.strip_prefix("pub(super) fn "))
            .or_else(|| rest.strip_prefix("fn "));
        let Some(after) = after_vis else { continue };
        let Some(paren) = after.find('(') else { continue };
        let name = &after[..paren];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            continue;
        }
        starts.push((idx, name.to_string()));
    }
    starts.push((src.len(), String::new()));
    let mut out = BTreeSet::new();
    for w in starts.windows(2) {
        let (s0, name) = (&w[0].0, &w[0].1);
        let body = &src[*s0..w[1].0];
        // ⛔ A BODY ENDS AT ITS BLOCK'S CLOSE (lane a 2026-10-23, G7): the next indented `fn` can be ~1,800 lines on, past
        // the impl's column-0 `}` and a doc comment that NAMES the writer (MEASURED: `Class::name` at node.rs:256 read as a
        // minting function from a `/// … record_note_payload(h, &n)` line at :899). A call is code, never a comment.
        let body = body.find("\n}").map_or(body, |e| &body[..e]);
        if name.ends_with("_for_test") || name == "record_note_payload" {
            continue;
        }
        if body.lines().any(|l| !l.trim_start().starts_with("//") && l.contains("record_note_payload(")) {
            out.insert(name.clone());
        }
    }
    out
}

pub const FILED_OPEN: &[&str] = &[
    // ⭐ "Block::output_notes via an ordinary spend" LEFT THIS LIST 2026-10-04: AUTHORITY closed by DB-223 Q7 (2026-10-02),
    // ONCE closed by DB-353 §13.6 and MEASURED by the db358 r3 (joiner's carried window) and r4 (reorg past the fold lag)
    // pins — see the Site's `once` answer.
    // ⭐ "Class::YieldClaim — the REWARD note" LEFT THIS LIST 2026-10-02 (DB-365 yield): the reward-follows-principal
    // carrier binds its value and owner, and the yield carrier welds the same value as the supply advance.
    // ⭐ "the notes of a credit-set object its class door refuses" LEFT THIS LIST 2026-10-02 (DB-365 producer variant):
    // DB-274 P4b decides every state-dependent object at the fold and strips a refused object's notes — the rogue
    // producer's 10⁹-unit note is no longer recorded on a peer (MEASURED, the Site's pin).
    // ⛔⛔⛔ ALL THREE FAIL THE **FOURTH** QUESTION ONLY — they answer WHO, HOW MUCH and ONCE soundly and
    // then mint node-locally. That is the cardinal, and until 2026-09-16 this census could not express it:
    // the question did not exist, so all three read as CLOSED. See `Travels`.
    //
    // ⭐ `Node::peg_in_confidential` LEFT THIS LIST 2026-09-16 (§CS): the PRIMARY ISSUANCE ROUTE of this
    // chain — deposit BTC/XMR, receive USDm — now publishes a `Class::PegIn` every peer re-admits.
];

/// ⛔⛔⛔ THE MIRROR QUESTION — WHO MAY *DESTROY* VALUE? A census of creation alone missed §BB.
///
/// HISTORY: until 2026-09-22 a deletion was applied from the block's header-bound `del_set`, map-authoritatively, and
/// MEASURED 2026-09-14 a producer named a victim's note and every peer deleted it (§BB). The Z-build retired the
/// deletion model: a note is spent when its NULLIFIER enters the spent set. The row `Block::del_set` stayed here until
/// 2026-10-03, naming a field that no longer existed — a stale row the sweep reported as an open exploit.
///
/// TODAY every retirement enters the spent set through ONE door, DB-367 `Node::lane_justified`: the tags of a PROVEN
/// transition, or the own ids (`chain_object::object_own_nullifiers`) of an ADMISSIBLE carried object. So the destruction
/// universe is (a) the rogue census's `burn` attack, one cell per chain-object class, checked against the source by
/// `rogue_census::destruction_universe_gaps`, and (b) the TRANSITIONS below, which carry tags that are not any class's.
/// (The bond transition is the class `BondTransition` and is censused there.)
pub const DESTRUCTION_BY_TRANSITION: &[(&str, crate::harness::rogue_census::Cell)] = &[
    (
        "note transition — a stated spend's nullifier at the fold",
        crate::harness::rogue_census::Cell::Pinned(
            "db367_a_lane_tag_nothing_proves_does_not_burn_a_victims_pending_spend_on_a_peer",
        ),
    ),
    (
        "cover transition — a multi-input group's tags at the fold",
        crate::harness::rogue_census::Cell::Open(
            "a cover group that does not verify contests nothing (DB-367, read in `respend_items`), but no peer-side pin \
             carries a forged group naming a victim's nullifier and asserts the victim's spend still lands",
        ),
    ),
];

/// The classes `chain_object::carried_note_payloads` can answer with a NON-EMPTY note list — read out of
/// the source itself, so the census cannot fall behind the code.
///
/// ⛔ TEXTUAL BY NECESSITY AND CALIBRATED BECAUSE OF IT: the arms build their notes from a decoded payload
/// this test has no way to synthesise, so the shape is read rather than executed. The calibration below
/// proves the reader can tell the two arm shapes apart.
pub fn classes_that_carry_notes(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let body_start = match src.find("pub fn carried_note_payloads") {
        Some(i) => i,
        None => return out,
    };
    let body_end = src[body_start..]
        .find("\npub fn ")
        .map(|i| body_start + i)
        .unwrap_or(src.len());
    let body = &src[body_start..body_end];
    let mut rest = body;
    while let Some(i) = rest.find("Class::") {
        rest = &rest[i..];
        let name: String = rest[7..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let arrow = match rest.find("=>") {
            Some(a) => a,
            None => break,
        };
        // The arm runs to the next `Class::` at this level, or to the end of the match.
        let arm_end = rest[arrow..]
            .find("\n        Class::")
            .map(|i| arrow + i)
            .unwrap_or(rest.len());
        let arm = &rest[arrow..arm_end];
        // An arm that ONLY ever yields `Vec::new()` creates no note. Anything that builds a `vec![…]` or
        // returns a decoded `.notes` list does — and so does an arm that hands back its object's own list
        // (`.carried_notes()`: finding A-F34 moved the creation's notes into `AssetCreateTx::carried_notes`, and this
        // reader, which knew only the two spellings above, then read the creation class as carrying nothing).
        let empties = arm.matches("Vec::new()").count();
        let builds = arm.matches("vec![").count() + arm.matches(".to_vec()").count() + arm.matches(".carried_notes()").count();
        if builds > 0 && empties == 0 {
            out.insert(name);
        } else if builds > 0 {
            out.insert(name); // mixed: it can carry a note on some path
        }
        rest = &rest[arrow + 2..];
    }
    out
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    fn chain_object_src() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/chain_object.rs"))
            .expect("the census reads the tree it audits")
    }

    /// ⛔⛔⛔ THE STANDARD. Every site answers AUTHORITY, AMOUNT and ONCE, or is filed as open by name.
    ///
    /// This is the test that would have gone red the moment `AssetMintTx` landed without a creator (§AT),
    /// red again when the creator gate landed without a one-shot (§AV), and red a third time when both
    /// were enforced only at the publisher (§AX) — because `Authority::AtTheGossipDoor` is the ONLY
    /// non-missing authority variant that a publisher-side check can honestly claim.
    #[test]
    fn every_value_creating_site_answers_authority_amount_and_once() {
        let mut unfiled = Vec::new();
        for s in SITES {
            if !s.is_closed() && !FILED_OPEN.contains(&s.name) {
                unfiled.push(format!("  ⛔ {} — {}", s.name, s.gaps().join(" · ")));
            }
        }
        assert!(
            unfiled.is_empty(),
            "⛔⛔⛔ A VALUE-CREATION SITE HAS AN UNANSWERED QUESTION AND IS NOT FILED AS OPEN.\n{}\n\n\
             Every one of these is an infinite-mint shape: AUTHORITY missing means anyone may create the \
             value, AMOUNT missing means the creator picks the number, ONCE missing means the party the \
             gate already trusts can repeat it without bound. Close it, or add it to FILED_OPEN with the \
             reason written into its Site — a hole nobody wrote down is how §AT, §AV and §AX each got a \
             full day of being called proven.",
            unfiled.join("\n")
        );
    }

    /// ⭐⭐⭐ EVERY FUNCTION THAT BRINGS A NOTE INTO LOCAL EXISTENCE IS IN THE CENSUS — derived from
    /// `node.rs` itself, over the ONE primitive that does it.
    ///
    /// ⛔⛔⛔ THE COMPLETENESS RULE BESIDE THIS ONE COULD NOT HAVE CAUGHT THE BIGGEST HOLE IN THE TREE.
    /// `every_note_carrying_class_is_in_the_census` derives its list from `Class::` variants in
    /// `chain_object.rs`. `Node::peg_in_confidential` — deposit BTC or XMR, receive USDm, the primary way
    /// this chain's money comes into existence — is an RPC HANDLER, not a chain-object class. It was
    /// therefore invisible to the census's own completeness test, absent from `SITES`, absent from the
    /// end-to-end register, and consequently absent from every list of "what is left" this project has
    /// produced. A census whose completeness is derived over the wrong universe is green by construction.
    ///
    /// ⭐ THE RIGHT UNIVERSE IS THE PRIMITIVE, NOT THE CLASS. `Node::record_note_payload` is the single
    /// call that puts a note into this node's own state; a site that creates value must reach it (directly
    /// or through the block it publishes). Deriving from its CALLERS finds handlers and classes alike, and
    /// a new mint path added tomorrow fails this test until its four answers are written down.
    ///
    /// MEASURED 2026-09-16, the callers this finds: `peg_in_confidential`, `execute_wrapped_mint_carried`,
    /// `execute_peg_out_burn_verified`, `execute_yield_claim`, `release_matured_bond` (plus the
    /// `_for_test` fixture, excluded by name). THREE of the five were in no census.
    ///
    /// ⛔ (2026-10-03) The `#[test]` that belonged to `every_local_note_minting_function_is_in_the_census` sat HERE,
    /// stacked on the next test, so that pin had NO attribute and never ran while its doc read as proof — found by the
    /// surface census's hollow-pin check. It is back on its own function below.
    /// ⭐⭐⭐ DB-196 — THE UNIVERSE CHECK DETECTS A GAP, so the readiness criterion it now feeds cannot
    /// be green by construction.
    ///
    /// `census_universe_gaps` is what makes *"value-creation sites not fully answered"* fail when the
    /// census stops covering its universe. A detector that cannot detect would re-create exactly the
    /// hole it was written for — criterion 4 reading ✅ on 2026-09-25 while its own completeness test
    /// was red — so it is exercised against a PLANTED gap before being trusted.
    #[test]
    fn the_universe_check_detects_a_minting_function_that_is_in_no_census() {
        // TODAY: no gaps. If this is ever non-empty the readiness report says so on its own.
        assert!(
            super::census_universe_gaps().is_empty(),
            "the live tree has a census universe gap: {:?}",
            super::census_universe_gaps()
        );

        // ⛔ NON-VACUITY: plant a minting function the census does not name, and the reader must find
        // it. This drives `local_note_minting_fns` — the same reader `census_universe_gaps` uses — so a
        // change that blinded the reader would fail here rather than silently emptying the universe.
        let planted = "impl Node {\n    pub fn a_brand_new_mint_route(&mut self) {\n        self.record_note_payload(1, &[]);\n    }\n}\n";
        let found = super::local_note_minting_fns(planted);
        assert!(
            found.contains("a_brand_new_mint_route"),
            "⛔ the reader did NOT see a function that calls the minting primitive — the universe check \
             is blind and the criterion it feeds would be green by construction. Found: {found:?}"
        );
        // And a function that does NOT mint must not be picked up, or everything is a "gap" and the
        // signal is worthless.
        let innocent = "impl Node {\n    pub fn just_reads(&self) -> u64 {\n        7\n    }\n}\n";
        assert!(
            super::local_note_minting_fns(innocent).is_empty(),
            "a function that never touches the primitive must not read as a mint path"
        );
    }

    /// ⭐ DB-195 — THE CUT LANDS WHERE IT IS MEANT TO, in both directions.
    ///
    /// A strip that removed too much would make the completeness rule green by construction — the exact
    /// failure its own doc warns about ("a census whose completeness is derived over the wrong universe
    /// is green by construction"). So this pins that PRODUCTION code survives, TEST code does not, and
    /// a `#[cfg(test)]` on something that is not a module drops nothing.
    #[test]
    fn strip_cfg_test_modules_finds_the_spans() {
        // a test FAMILY module with an extra attribute is cut; a non-test cfg module is kept
        let fam = "fn keep_a() {}\n#[cfg(all(test, feature = \"pins-node\"))]\n#[allow(unused_imports)]\npub(crate) mod pins {\n    fn drop_pin() {}\n}\n#[cfg(feature = \"arti-onion\")]\nmod onion {\n    fn keep_onion() {}\n}\n";
        let cut = super::strip_cfg_test_modules(fam);
        assert!(cut.contains("keep_a") && cut.contains("keep_onion"), "production code survives: {cut:?}");
        assert!(!cut.contains("drop_pin"), "a pins-family module's body is cut: {cut:?}");
        let src = "fn keep_me() {}\n#[cfg(test)]\npub(crate) mod tests {\n    fn drop_me() {}\n}\nfn keep_me_too() {}\n";
        let cut = super::strip_cfg_test_modules(src);
        assert!(cut.contains("keep_me"), "production code before the module survives: {cut:?}");
        assert!(cut.contains("keep_me_too"), "production code AFTER the module survives: {cut:?}");
        assert!(!cut.contains("drop_me"), "the test module's body is cut: {cut:?}");

        // ⛔ A `#[cfg(test)]` that is NOT a module must not trigger a cut — otherwise a single attribute
        // on a helper would silently delete the rest of the file from the census's universe.
        let lone = "fn a() {}\n#[cfg(test)]\nfn b_helper() {}\nfn c() {}\n";
        let cut2 = super::strip_cfg_test_modules(lone);
        assert!(
            cut2.contains("fn a") && cut2.contains("fn c"),
            "a non-module #[cfg(test)] must not cut production code: {cut2:?}"
        );

        // ⭐ AND ON THE REAL FILE: the production minters survive the cut.
        let real = super::node_production_source().expect("node source");
        let after = super::strip_cfg_test_modules(&real);
        assert!(
            after.contains("fn peg_in_confidential"),
            "⛔ the cut removed `peg_in_confidential` — the way USDm is actually issued. A strip that \
             eats production code makes this whole census green by construction."
        );
        assert!(
            after.len() * 2 > real.len(),
            "the cut removed more than half of node.rs ({} -> {} bytes) — far too much to be test \
             modules alone",
            real.len(),
            after.len()
        );
    }

    #[test]
    fn every_local_note_minting_function_is_in_the_census() {
        let src = super::node_production_source().expect("the node source is readable");
        let minters = super::local_note_minting_fns(&src);
        assert!(
            minters.len() >= 3,
            "⛔ THE READER FOUND {} minting function(s). A derivation that finds nothing is green and \
             worthless — the same SILENCE failure the seam census was built after. Found: {minters:?}",
            minters.len()
        );
        let named: BTreeSet<String> = SITES
            .iter()
            .filter_map(|s| s.name.strip_prefix("Node::").map(str::to_string))
            .collect();
        let missing: Vec<&String> = minters.difference(&named).collect();
        assert!(
            missing.is_empty(),
            "⛔⛔⛔ A FUNCTION MINTS A NOTE AND IS IN NO CENSUS: {missing:?}\n\
             It brings value into existence, so it must answer AUTHORITY / AMOUNT / ONCE / TRAVELS like \
             every other site. This is the rule that would have caught `Node::peg_in_confidential` — the \
             BTC/XMR deposit route, the way USDm is actually issued — which sat outside every census while \
             minting node-locally.\n(minting functions read from the source: {minters:?})"
        );
    }

    /// ⛔ EVERY CLASS THAT CAN CARRY A NOTE IS IN THE CENSUS — derived from `chain_object.rs`, so adding
    /// a note-bearing class to the chain fails here until its three answers are written down.
    #[test]
    fn every_note_carrying_class_is_in_the_census() {
        let src = chain_object_src();
        let carriers = classes_that_carry_notes(&src);
        assert!(
            !carriers.is_empty(),
            "⛔ THE READER FOUND NO NOTE-CARRYING CLASS AT ALL. A census over an empty list is green and \
             worthless — this is the SILENCE failure `harness::seam` was built after."
        );
        let named: BTreeSet<String> = SITES
            .iter()
            .filter_map(|s| s.name.strip_prefix("Class::").map(str::to_string))
            .collect();
        let missing: Vec<&String> = carriers.difference(&named).collect();
        assert!(
            missing.is_empty(),
            "⛔⛔⛔ A CHAIN-OBJECT CLASS CARRIES NOTES AND IS NOT IN THE VALUE-CREATION CENSUS: {missing:?}\n\
             It brings value into existence, so it must answer AUTHORITY / AMOUNT / ONCE like every other \
             site. Add it to SITES with its three answers.\n\
             (note-carrying classes read from the source: {carriers:?})"
        );
    }

    /// ⛔ A CENSUS MAY NOT CITE A MECHANISM THAT DOES NOT EXIST — that is how a register survives its own
    /// fix being reverted. Every named symbol must be findable in `src/`.
    #[test]
    fn every_cited_mechanism_exists_in_the_tree() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut all = String::new();
        fn walk(dir: &std::path::Path, out: &mut String) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    if let Ok(s) = std::fs::read_to_string(&p) {
                        out.push_str(&s);
                    }
                }
            }
        }
        walk(std::path::Path::new(root), &mut all);

        let mut dead = Vec::new();
        for s in SITES {
            let cites: Vec<&str> = match (&s.authority, &s.amount, &s.once) {
                _ => {
                    let mut v = Vec::new();
                    if let Authority::AtTheGossipDoor(c) | Authority::BondedThreshold(c) | Authority::AtTheFold(c) = s.authority {
                        v.push(c);
                    }
                    if let Amount::DerivedByEveryNode(c) | Amount::BoundIntoTheAuthority(c) = s.amount {
                        v.push(c);
                    }
                    match s.once {
                        Once::DeletionTransition(c)
                        | Once::Nullifier(c)
                        | Once::CommitmentIsTheIdentity(c) => v.push(c),
                        Once::Missing(_) => {}
                    }
                    v
                }
            };
            for c in cites {
                // A citation's leading token is the symbol; the rest is prose.
                for tok in c.split_whitespace().take(1) {
                    let sym = tok.trim_end_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
                    let leaf = sym.rsplit("::").next().unwrap_or(sym);
                    if leaf.len() > 3
                        && leaf.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase())
                        && !all.contains(leaf)
                    {
                        dead.push(format!("{} cites `{leaf}`, which is nowhere in src/", s.name));
                    }
                }
            }
        }
        assert!(
            dead.is_empty(),
            "⛔⛔⛔ THE CENSUS CITES A MECHANISM THAT DOES NOT EXIST:\n  {}\n\n\
             A register that outlives its own fix is worse than no register: it reports a hole as closed \
             by naming a symbol somebody reverted.",
            dead.join("\n  ")
        );
    }

    /// ⭐⭐⭐ CALIBRATION — REFUTATION BEFORE GREEN. Three instruments, three armed attacks.
    ///
    /// ⛔ Every green above is worthless unless each check can be made to FAIL. `harness::seam` caught
    /// three blind detectors this way, each of which printed a perfectly clean list.
    #[test]
    fn the_census_detects_each_hole_it_claims_to_detect() {
        // 1. THE STANDARD fires on a site missing any one of the three — one at a time, so a check that
        //    only ever looks at `authority` cannot pass this.
        for (label, bad) in [
            (
                "AUTHORITY",
                Site {
                    name: "calibration::no_authority",
                    authority: Authority::Missing("nothing asks who — this is §AT's shape"),
                    amount: Amount::DerivedByEveryNode("x"),
                    once: Once::Nullifier("x"),
                
                    travels: Travels::AsAChainObject("calibration fixture — only the AUTHORITY field is missing here"),
    },
            ),
            (
                "AMOUNT",
                Site {
                    name: "calibration::no_amount",
                    authority: Authority::AtTheGossipDoor("x"),
                    amount: Amount::Missing("the creator picks the number"),
                    once: Once::Nullifier("x"),
                
                    travels: Travels::AsAChainObject("calibration fixture — only the AMOUNT field is missing here"),
    },
            ),
            (
                "ONCE",
                Site {
                    name: "calibration::no_once",
                    authority: Authority::AtTheGossipDoor("x"),
                    amount: Amount::DerivedByEveryNode("x"),
                    once: Once::Missing("nothing stops a second — this is §AV's shape"),
                
                    travels: Travels::AsAChainObject("calibration fixture — only the ONCE field is missing here"),
    },
            ),
        ] {
            assert!(
                !bad.is_closed(),
                "⛔ CALIBRATION FAILED: a site with {label} missing was judged CLOSED. The standard is \
                 blind to that column, so every green it has ever printed for it is vacuous."
            );
            assert_eq!(bad.gaps().len(), 1, "{label}: exactly one gap must be named");
        }
        // A site answering all three must pass, or the standard refuses everything and proves nothing.
        let good = Site {
            name: "calibration::sound",
            authority: Authority::AtTheGossipDoor("x"),
            amount: Amount::DerivedByEveryNode("x"),
            once: Once::Nullifier("x"),
        
            travels: Travels::AsAChainObject("calibration fixture — the all-answered control"),
    };
        assert!(good.is_closed(), "⛔ CALIBRATION FAILED: the standard refuses a sound site.");

        // 2. THE CLASS READER can tell a note-carrying arm from an empty one. Both shapes are real —
        //    copied from `carried_note_payloads` itself — so this measures the reader, not a toy.
        let fixture = "pub fn carried_note_payloads(blob: &[u8]) -> Option<Vec<Vec<u8>>> {\n\
             \x20   Some(match class {\n\
             \x20       Class::CalibCarries => vec![Thing::decode(payload)?.note],\n\
             \x20       Class::CalibEmpty => {\n\
             \x20           Thing::decode(payload)?;\n\
             \x20           Vec::new()\n\
             \x20       }\n\
             \x20   })\n}\n\npub fn next() {}\n";
        let got = classes_that_carry_notes(fixture);
        assert!(
            got.contains("CalibCarries"),
            "⛔ CALIBRATION FAILED: the reader MISSED a class that carries a note. A census that cannot \
             see a note-bearing arm is the SILENCE failure — it would report a clean list forever. \
             (read: {got:?})"
        );
        assert!(
            !got.contains("CalibEmpty"),
            "⛔ CALIBRATION FAILED: the reader counted an arm that carries NOTHING. A reader that flags \
             everything is as useless as one that flags nothing — it trains its reader to ignore it. \
             (read: {got:?})"
        );

        // 3. THE REAL SOURCE is not empty — the reader is pointed at the file it claims to audit.
        let real = classes_that_carry_notes(&chain_object_src());
        assert!(
            real.contains("AssetMint"),
            "⛔ CALIBRATION FAILED: `AssetMint` carries a note in `carried_note_payloads` and the reader \
             did not see it in the REAL source. The fixture passing while the real file reads clean is \
             exactly the drift this catches. (read: {real:?})"
        );
    }

    /// The census as a report — what is closed, what is open, and what each open one still owes.
    #[test]
    fn value_creation_census_report() {
        let closed = SITES.iter().filter(|s| s.is_closed()).count();
        eprintln!(
            "\n⭐ VALUE-CREATION CENSUS — {closed}/{} sites answer AUTHORITY / AMOUNT / ONCE",
            SITES.len()
        );
        for s in SITES {
            if s.is_closed() {
                eprintln!("  ✅ {}", s.name);
            } else {
                eprintln!("  ⛔ {} — {}", s.name, s.gaps().join(" · "));
            }
        }
        eprintln!(
            "  (note-carrying classes derived from chain_object.rs: {:?})",
            classes_that_carry_notes(&chain_object_src())
        );
    }
}

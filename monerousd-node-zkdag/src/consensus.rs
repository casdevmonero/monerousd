// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Consensus block-validity gate (brick 6).
//!
//! Split into two phases so gossip's out-of-order delivery never rejects a merely-early block:
//! * [`validate_structural`] — self-contained checks (no DAG lookups): version, parent count
//!   against the governance-tunable `dag_width`, duplicate parents, future-timestamp drift, and
//!   the tx-merkle-root binding. Safe to apply the instant a block arrives, even before its
//!   parents are known — it rejects a block only for its OWN malformedness.
//! * [`validate_contextual`] — checks that need the parents present: parent membership,
//!   median-time-past, and the DAA-expected work. Returns [`ConsensusError::UnknownParent`] when a
//!   parent is not yet in the DAG so the caller buffers the block as an orphan and retries.
//!
//! This is the structural/semantic gate. The ZK-proof soundness gate (verifying each block's proof via
//! the pure-Rust usdm-decider WHIR light decider — the whole-chain block decider, plus the per-tx carriers which ride
//! the live HVZK-WHIR light decider) is the companion consensus check wired in the ZK-verify brick; both
//! must pass before a block is final.

use std::collections::HashSet;

use crate::block::{Block, BlockHeader, BlockId};
use crate::dag::Dag;
use crate::params::ChainParams;

/// Why a block failed consensus validation. Every variant rejects the OFFENDING block only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("a non-genesis block has no parents")]
    NoParents,
    #[error("too many parents ({got} > dag_width {width})")]
    TooManyParents { got: usize, width: usize },
    #[error("duplicate parent references")]
    DuplicateParents,
    /// The block merges more blocks AT ONCE than the protocol shape allows. Not an age/reach bound: the
    /// un-merged blocks stay in the DAG and the next block absorbs them, so no note is refused.
    #[error("block merges {got} blocks at once, more than the protocol shape bound {bound} — the rest are merged by the next block, none are dropped")]
    MergesetTooLarge { got: usize, bound: usize },
    #[error("parent {0} unknown (buffer as orphan)")]
    UnknownParent(BlockId),
    #[error("timestamp {ts} <= median-time-past {mtp}")]
    TimestampTooEarly { ts: u64, mtp: u64 },
    #[error("timestamp {ts} too far in the future (> {limit})")]
    TimestampTooFarFuture { ts: u64, limit: u64 },
    #[error("declared work {got} != DAA-expected {expected}")]
    WrongWork { expected: u128, got: u128 },
    #[error("tx_merkle_root does not commit the tx id list")]
    TxRootMismatch,
    /// The header's `output_notes_root` does not commit to the block's own `output_notes`.
    ///
    /// Named separately from [`Self::TxRootMismatch`] because it is a different claim: that one says the
    /// block lied about WHICH TXS it selected, this one says it lied about the NOTE BYTES it ships. Two
    /// nodes accepting a block whose notes are not the notes its id commits to end up holding "the same
    /// block" with different payloads, which is what made their spend roots diverge.
    #[error("header note_commitments_root does not commit to the block's own constant-width note carrier")]
    NoteCommitmentsRootMismatch,
    /// The block's note carrier is not exactly the fixed width. ⛔ A short or long carrier STATES A COUNT
    /// BY ITS LENGTH, which is the entire defect DB-165 removes — so a wrong width is not a carrier at all.
    #[error("the block's note carrier is not the fixed constant width")]
    NoteCarrierWidth,
    #[error("header output_notes_root does not commit to the block's own output_notes")]
    OutputNotesRootMismatch,
    /// The block's note payload is wider than the fixed DA blob ([`crate::block::DA_NOTES_BLOB_BYTES`]): its tail
    /// would be committed past every sampler's index range. The template never packs more (`select_for_template`).
    #[error("the block's note payload is wider than the fixed DA blob")]
    OutputNotesOverWidth,
    /// The header's `nullifier_tags_root` does not commit to the block's own carried tag set.
    #[error("header nullifier_tags_root does not commit to the block's own nullifier tags")]
    NullifierTagsRootMismatch,
    /// §22c — a row of the block states a spend that no transaction carried beside it proves to this node
    /// (`spend_evidence::block_spends_are_evidenced`), or the copy arrived without the body it must be judged with.
    #[error("a stated spend is not a carried transaction this node verified")]
    SpendNotEvidenced,
    /// The header's `oli_tags_root` does not commit to the block's own carried locator tags.
    #[error("header oli_tags_root does not commit to the block's own oli_tags")]
    OliTagsRootMismatch,
    /// ⭐ §BA — the header's `credit_set_root` does not commit to the block's own credit set. An
    /// unbound justification sidecar is worse than none: a relay could append the object that excuses
    /// whatever note it wanted to plant, with the block id unchanged.
    #[error("header credit_set_root does not commit to the block's own credit_set")]
    CreditSetRootMismatch,
    /// ⭐⭐⭐ DB-224 — an entry of the block's credit set is not in CARRIAGE form: it does not parse, is not
    /// a framed object of a known class, or still carries a note PAYLOAD where only a 64-byte reference
    /// may stand (`chain_object::carriage_of`). A real payload on the block wire is the only secret input
    /// of `cover::block_cover_secret` — refusing the block is what makes "no payload byte rides a block" a
    /// property of the CHAIN rather than of a producer's courtesy.
    #[error("the block's credit set carries something other than carriage-form objects")]
    CreditSetNotCarriage,
    /// §22b: the sealed set names a wide object (by its carriage hash) whose bytes this body does not hold — an
    /// incomplete body, never a smaller set (BIP152: a compact block is not a block until its named txs are in hand).
    #[error("the block's credit set names a wide object this body does not carry")]
    CreditSetWideMissing,
    /// ⭐⭐⭐ DB-224 — a carried object names a note this block's own note carrier does not commit. The
    /// objects travel now, so without this a producer could apply a valid peg-in's ledger transition on
    /// every node (burning its deposit id) while leaving its minted note out of the block: evidence with
    /// no subject is a griefing — and funds-loss — attack, not a harmless extra.
    #[error("the block's credit set names a note the block's own note carrier does not commit")]
    CreditObjectWithoutSubject,
    /// The header's `account_targets_root` does not commit to the block's own carried account targets.
    #[error("header account_targets_root does not commit to the block's own account_targets")]
    AccountTargetsRootMismatch,
    /// ⭐ H5 / DB-273 (C): a block carries NO account targets (the per-wallet bucket linker, census `Block::account_targets`).
    #[error("the block carries account targets — the per-wallet bucket linker is retired (DB-273 C)")]
    AccountTargetsCarried,
    /// The carried deletion set does not hash to `header.del_set_root` — stripped/swapped in flight.
    #[error("header del_set_root does not commit to the block's own carried deletion set")]
    DelSetRootMismatch,
    /// The carried validator-bond set does not hash to `header.bond_set_root` — stripped/swapped in flight.
    #[error("header bond_set_root does not commit to the block's own carried bond set")]
    BondSetRootMismatch,
    /// DB-223: the carried note / cover / membership transitions do not hash to `header.transitions_root` — a
    /// transition stripped, replaced or added in flight.
    #[error("header transitions_root does not commit to the block's own carried transitions")]
    TransitionsRootMismatch,
    /// The carried directory set does not hash to `header.dir_set_root` — stripped/swapped in flight.
    #[error("header dir_set_root does not commit to the block's own carried directory set")]
    DirSetRootMismatch,
    /// The carried evidence does not hash to `header.tag_evidence_root` — stripped/swapped in flight.
    #[error("header tag_evidence_root does not commit to the block's own carried evidence")]
    TagEvidenceRootMismatch,
    /// The carried letter set does not hash to `header.letter_set_root` — stripped/swapped in flight.
    #[error("header letter_set_root does not commit to the block's own carried letter set")]
    LetterSetRootMismatch,
    /// The carried letter set is not the CONSTANT cover-padded shape (LETTER_CMS_PER_BLOCK x 32 bytes) — a
    /// short/long set would leak real mail volume (digital-cash) and desync the letter accumulator fold.
    #[error("block letter_set is {got} bytes, not the constant {want}-byte cover shape")]
    LetterSetBadShape { got: usize, want: usize },
    #[error("invalid header version")]
    BadVersion,
    #[error("block carries {got} txs, over the fixed-shape cap {cap}")]
    TooManyTxs { got: usize, cap: usize },
    /// #73 PoUW invalid: the PQ-PoUW digest of the header preimage does not meet the `work` target, and/or
    /// the non-outsourceable coinbase-key proof `pi` fails (bad `pow_bind = H(pi)`, wrong note_cm, or wrong
    /// challenge). A miner MUST hold the coinbase spend key AND grind a valid PoUW hash — hashpower alone
    /// cannot forge it. Rejected fail-closed on the BAD block only (never halts the DAG).
    #[error("#73 PoUW invalid (PQ-PoUW target or non-outsourceable pi failed)")]
    InvalidPoW,
    /// The block carries a settlement aggregate (`Block.settlement`) that does NOT verify against the block's
    /// own carriers — a forged/mismatched O(1) settlement proof. The aggregate is an OPTIONAL witness (a block
    /// without one is valid; the node falls back to per-tx verify), so this rejects ONLY a block that ships a
    /// present-but-invalid aggregate — fail-closed on the BAD block only, never a halt.
    #[error("block-carried settlement aggregate does not verify against its carriers")]
    InvalidSettlement,
    /// The block's carried `nullifier_witnesses` do not replay against this node's O(1) `nullifier_acc` — a
    /// stale/forged non-membership witness (a double-spend or a lie), OR the set is not the CONSTANT per-block
    /// length (a volume-privacy violation / short pad). The trustless carried-witness path is MANDATORY: a spend
    /// with no valid witness is rejected fail-closed on the BAD block only, never through an unchecked route.
    #[error("block-carried nullifier witnesses do not replay against the O(1) accumulator")]
    InvalidNullifierWitness,
}

/// ⛔⛔⛔ THE HEADER-ONLY HALF OF [`validate_structural`] — THE ONE SITE EVERY BLOCK DOOR SHARES.
///
/// WHY IT EXISTS (§9.6 question 6, measured 2026-09-07): the gossip door ran these rules and the
/// four non-gossip block doors ran NONE of them, because the only function that stated them also
/// stated the BODY-commitment rules — and a shell (header + tx ids, the shape every heal, carry and
/// anchor door moves) carries no body to check those against. So the doors that could not run the
/// whole function ran none of it, and a header with a century-in-the-future timestamp, a duplicate
/// parent list or a tx list its own merkle root does not commit to entered the DAG unexamined.
///
/// The split is by WHAT THE OBJECT CARRIES, not by which caller wants which rule: everything below
/// is decidable from `header` + `tx_ids` alone, so every door can run all of it, and
/// [`validate_structural`] is exactly this function plus the body-commitment rules for a door that
/// holds the body. There is one behaviour table and one place to change it.
///
/// `now_ts` is `None` for a door that holds NO bound on wall-clock time — the DSYNC anchor and fold-
/// carry doors place blocks from a chain AHEAD of this node, so no clock this node can derive is an
/// upper bound on their timestamps (a node an hour behind would refuse the very bundle that heals
/// it). Those doors state that gap in their own doc comments. Every door that CAN name a `now_ts`
/// passes one and gets the identical drift rule the gossip door runs.
pub fn validate_header_structural(
    h: &BlockHeader,
    tx_ids: &[BlockId],
    now_ts: Option<u64>,
    params: &ChainParams,
) -> Result<(), ConsensusError> {
    if h.version == 0 {
        return Err(ConsensusError::BadVersion);
    }
    if !h.is_genesis() {
        if h.parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }
        if h.parents.len() > params.dag_width {
            return Err(ConsensusError::TooManyParents {
                got: h.parents.len(),
                width: params.dag_width,
            });
        }
        let uniq: HashSet<&BlockId> = h.parents.iter().collect();
        if uniq.len() != h.parents.len() {
            return Err(ConsensusError::DuplicateParents);
        }
    }
    if let Some(now) = now_ts {
        let limit = now.saturating_add(params.max_ts_drift_ms);
        if h.timestamp > limit {
            return Err(ConsensusError::TimestampTooFarFuture {
                ts: h.timestamp,
                limit,
            });
        }
    }
    let recomputed = crate::miner::tx_merkle_root(tx_ids);
    if h.tx_merkle_root != recomputed {
        eprintln!(
            "[txroot] MISMATCH: header={:?} recomputed={:?} tx_ids.len={}",
            h.tx_merkle_root,
            recomputed,
            tx_ids.len(),
        );
        return Err(ConsensusError::TxRootMismatch);
    }
    // Constant-block-shape CAP (ported from the old tree's v36_shape): a block carries AT MOST
    // BLOCK_FIXED_TX_COUNT txs, so no block can exceed the fixed shape an honest producer fills to. Fail-
    // CLOSED on the over-cap block ONLY; a block with FEWER (the producer's cover fill is best-effort) still
    // validates — no-halts by construction. ([[crate::cover]])
    if !crate::cover::within_block_tx_cap(tx_ids.len()) {
        return Err(ConsensusError::TooManyTxs {
            got: tx_ids.len(),
            cap: crate::cover::BLOCK_FIXED_TX_COUNT,
        });
    }
    Ok(())
}

/// ⛔⛔⛔ THE BODY-COMMITMENT HALF — THE ONE LIST EVERY DOOR THAT HOLDS BODY BYTES READS.
///
/// WHY IT MOVED OUT OF [`validate_structural`] (adversarial review, 2026-09-08). These rules lived
/// inline in that function, which only a door holding a WHOLE block can call. Every OTHER door —
/// the #29 DSYNC adopt, the fold carry's ancestor and carried-block installs, the anchor install,
/// the block-lane shell graft — moves an object that carries SOME body bytes AND APPLIES THEM, and
/// ran none of these rules. `Block::id()` is `header.id()`, so an id binds the HEADER ONLY: a relay
/// that rewrites `output_notes` / `account_targets` on a certified block produces the SAME id, the
/// SAME `chain_acc`, and the adopting node files the attacker's bytes at a real block's address.
/// MEASURED by the review's own two attacks, `lane1_adversarial_review_tests`:
/// `review_a3_the_certified_tip_blocks_body_bytes_are_not_bound_by_the_completeness_law` and
/// `review_a3_the_carried_blocks_bodies_are_not_bound_by_the_carry_digest`.
///
/// THE LAW, stated once for both doors. A body part is admissible iff
/// * it is PRESENT and its bytes reproduce the header's own commitment for that part, or
/// * it is ABSENT (empty) **and the caller is a door that accepts a REDUCED carrier** — a shell, a
///   fold-carry block, a DSYNC bundle block. An absent part APPLIES NOTHING, so there is nothing
///   for a forger to substitute; a PRESENT part is checked against the commitment the miner sealed
///   into the id before the PoW, which no third party can reopen.
///
/// The two doors differ in exactly ONE bit — whether ABSENT is admissible — so this is ONE function
/// with two named entry points, [`validate_full_body_commitments`] (the gossip door, which holds
/// the whole body) and [`validate_carried_body_commitments`] (every door that moves a reduced
/// carrier). One behaviour table; the two cannot drift.
///
/// ⛔ WHAT THIS DOES NOT CLOSE, written where the rule is and not in a summary: with `absent_ok` a
/// relay may STRIP a carried part. It cannot FORGE one — stripping injects nothing, and every
/// attack above is an injection — but the adopter then files nothing at that address, which on the
/// DSYNC tip is the findability downgrade `Block::oli_tags` names ("a note nobody can LOCATE is a
/// note nobody can spend"). Bounded by the by-id record lane, which re-asks for a rid this node
/// holds no bytes for. It is REPORTED OPEN, not assumed closed: closing it means putting the
/// SHIPPED bytes inside `sync::sync_binding`'s preimage, because the serve deliberately ships a
/// REDUCED body (`Node::build_sync_bundle` blanks every sidecar and every carried note payload),
/// and no header commitment can bind bytes the header does not commit to.
///
/// Genesis is exempt on both doors: it carries no body and commits the fixed empty-payload hashes.
/// Fail-CLOSED on the BAD BLOCK ONLY — a mismatch rejects that block and nothing else, so a
/// tampering relay isolates itself and chain progress is never gated on it.
fn body_commitments_admit(block: &Block, absent_ok: bool) -> Result<(), ConsensusError> {
    let h = &block.header;
    if h.is_genesis() {
        return Ok(());
    }
    // The ONE predicate for the SMALL sidecars. `da_sidecar_root_of` IS `blake3(bytes)` — the exact
    // function `Node::produce` seals them with — so producer and verifier cannot drift. ⛔ The NOTES root
    // is no longer one of them: it is a chunk-merkle root and is checked separately below.
    let bound = |bytes: &[u8], root: crate::hash::Hash32| -> bool {
        (absent_ok && bytes.is_empty()) || root == crate::block::da_sidecar_root_of(bytes)
    };
    // §POLES: the three LENGTH-PREFIXED sidecars (bond_set, credit_set, dir_set) are padded to a
    // constant shape; their roots commit to REAL content (before padding). Strip the cover padding
    // before hashing. NOT used for oli_tags/account_targets/letter_set whose format is not
    // length-prefixed frames.
    let bound_padded = |bytes: &[u8], root: crate::hash::Hash32| -> bool {
        let real = &bytes[..crate::block::sidecar_real_len(bytes)];
        (absent_ok && real.is_empty()) || root == crate::block::da_sidecar_root_of(real)
    };
    // The id folds `output_notes_root` and `nullifier_tags_root`, but folding a commitment into the id does
    // NOTHING on its own: a receiver derives the id from the HEADER, so a body that disagrees with the
    // header's own commitment yields the SAME id and slips straight through. `OutputNotesRootMismatch` was
    // declared for exactly this and was never returned from anywhere — the notes half of the binding has
    // been unenforced since it was added, which is the hole it was written to close.
    // ⭐ THE NOTES ROOT IS THE ONE SIDECAR THAT IS A CHUNK-MERKLE ROOT — see `da_notes_root_of`. It is the
    // bulk payload, so it is the one that has to be holdable in PIECES; every other root below stays the
    // flat `blake3(bytes)` because a small sidecar is served whole or not at all.
    // ⛔⛔⛔ DB-165 — THIS ROOT NO LONGER BINDS A TRAVELLING FIELD, AND SAYING SO IS THE POINT.
    //
    // `output_notes` is `#[serde(skip)]` since its LENGTH stated the block's real note count. A receiver
    // REHYDRATES it from the block's own `tx_ids` and checks every derived note against
    // `note_commitments`, which DOES travel, is constant-width, and is bound by the header and the PoW.
    // So the binding that matters is the carrier's, enforced below — and this check now only holds a node
    // that DID derive a body to the producer's own encoding of it. A node missing a tx derives a shorter
    // body and must NOT be refused for it: that would make a pool gap a consensus failure, which is
    // exactly the local-state-as-truth shape §BA closed.
    if block.output_notes.len() > crate::block::DA_NOTES_BLOB_BYTES {
        return Err(ConsensusError::OutputNotesOverWidth);
    }
    if !block.output_notes.is_empty()
        && h.output_notes_root != crate::block::da_notes_root_of(&block.output_notes)
    {
        return Err(ConsensusError::OutputNotesRootMismatch);
    }
    // ⭐⭐⭐ DB-165 — THE CONSTANT-WIDTH NOTE CARRIER, ENFORCED ON BOTH AXES.
    //
    // WIDTH FIRST, and it is a privacy gate rather than a soundness one: a carrier that is not exactly
    // `BLOCK_NOTE_COMMITMENTS_BYTES` states the block's real note count by its own length, which is the
    // defect this field exists to remove (MEASURED 2026-09-24: `output_notes` 0 B quiet, 5,765 B busy =
    // exactly 5 notes). A block whose carrier is short is not "slightly less private" — it is the old
    // leak, so it is refused outright.
    //
    // THEN THE BINDING, for the same reason the notes and tags twins are bound: a receiver derives the id
    // from the HEADER, so a body disagreeing with the header's own commitment yields the SAME id and
    // slips through. Folding a root into the id does nothing unless somebody CHECKS the body against it.
    //
    // `absent_ok` covers the header-shell path exactly as it does above: a shell carries no body at all,
    // and a shell is never applied — it is an ancestor placeholder.
    if !(absent_ok && block.note_commitments.is_empty()) {
        if block.note_commitments.len() != crate::cover::BLOCK_NOTE_COMMITMENTS_BYTES {
            return Err(ConsensusError::NoteCarrierWidth);
        }
        if h.note_commitments_root != crate::hash::Hash32::hash(&block.note_commitments) {
            return Err(ConsensusError::NoteCommitmentsRootMismatch);
        }
    }
    // The spend-side twin: the tag set is what every node folds into A_tip and writes to its DA-nf
    // shard, so an altered set would leave two nodes holding one block id while folding DIFFERENT
    // spends. The carried height-1 fold cannot substitute — it is publicly re-provable in ~0 ms, so a
    // relay can strip the tags AND mint a matching fold. Only the id can bind them.
    let tags = &block.nullifier_proof.padded_tags;
    if !((absent_ok && tags.is_empty())
        || h.nullifier_tags_root == crate::block::nullifier_tags_root_of(tags))
    {
        return Err(ConsensusError::NullifierTagsRootMismatch);
    }
    // ⭐⭐⭐ P4′a — THE TWO FINDABILITY SIDECARS, ENFORCED THE SAME WAY AND FOR A SHARPER REASON.
    //
    // The notes and tags halves above protect the money's EXISTENCE and its SPENT-state. These protect
    // the owner's ability to FIND it, which is the difference between a note that is on chain and a note
    // that is spendable: a locator tag stripped in flight puts the note in no index on the receiving node,
    // and its owner can never look it up from their seed. Measured 2026-08-10 — one node indexed 4 tags,
    // its peer indexed 2 for the same blocks, and the notes of send 2 were on chain and invisible.
    //
    // Unenforced, this is also what would make the P4′b backfill unsound: a restarting node rebuilds its
    // locator index from sidecars an arbitrary peer hands it, and the ONLY thing that makes an arbitrary
    // peer safe to accept from is that the id binds what it serves.
    if !bound(&block.oli_tags, h.oli_tags_root) {
        return Err(ConsensusError::OliTagsRootMismatch);
    }
    if !bound(&block.account_targets, h.account_targets_root) {
        return Err(ConsensusError::AccountTargetsRootMismatch);
    }
    if !block.account_targets.is_empty() {
        return Err(ConsensusError::AccountTargetsCarried);
    }
    // The bond sidecar binds identically: a stripped or swapped bond set is a DIFFERENT block,
    // never a quietly finality-blind one (validators would diverge per-node otherwise).
    if !bound_padded(&block.bond_set, h.bond_set_root) {
        return Err(ConsensusError::BondSetRootMismatch);
    }
    // ⭐ DB-223 — THE CARRIED TRANSITIONS BIND THE SAME WAY. The note, cover and membership transitions are the only
    // evidence a peer holding no transaction body has for a block's spend outputs and inputs; unbound, a relay could
    // STRIP a genuine one and the copy would keep this id, and a peer grafting it would refuse what every other peer
    // records. A reduced carrier (`absent_ok`) may omit ALL of them, exactly as it omits every other sidecar; any it
    // carries must be the header's.
    let carries_a_transition =
        block.note_transition.is_some() || block.cover_transition.is_some() || block.member_transition.is_some();
    if !(absent_ok && !carries_a_transition) && h.transitions_root != block.transitions_root() {
        return Err(ConsensusError::TransitionsRootMismatch);
    }
    // ⭐ §BA — THE JUSTIFICATION SIDECAR BINDS LIKE THE REST, AND IT IS THE ONE WHERE AN UNBOUND CARRY
    // WOULD BE SELF-DEFEATING: `graft_admitted_notes` admits a non-spend note only when an object in this
    // set justifies it, so a relay that could append to the set could excuse any planted note it liked
    // while keeping the block id. Same fail-closed-on-the-bad-block rule; the DAG never halts on it.
    // ⛔⭐⭐⭐ DB-191 — DB-165 TOOK `credit_set` OFF THE WIRE AND LEFT THIS BIND CHECKING THE EMPTY FIELD.
    //
    // `Block::credit_set` is `#[serde(skip)]` (its LENGTH stated the real credit count), so a RECEIVED
    // block arrives with it empty and `rehydrate_block_body` rebuilds it at ingest — which happens
    // AFTER this pre-verify. So `bound(&[], h.credit_set_root)` failed for every block that carried a
    // real credit set, and the block was refused.
    //
    // ⛔ MEASURED, ecosystem gate 35 (2026-09-25): `CreditSetRootMismatch` x8 and
    // `[credit-auth] ⛔ UNATTESTED: 0 attestation(s)` x21, with step 2 failing
    // `balance never reached 25.0 spendable (last: 0.0)` — the faucet credit's own block refused by its
    // peer. That is why step 2 read as "intermittent" at roughly 50/50: it depended on whether the
    // block carrying the credit needed a credit set at all.
    //
    // ⛔ AND I SHIPPED IT. My DB-165 privacy measurement showed `credit_set 0 B on the wire`, which is
    // exactly what DB-165 wanted, and I never asked whether the CONSENSUS BINDING still held. A field
    // measured absent on the wire is not the same question as a field still bound by its root.
    //
    // ⭐ THE BIND IS NOT DROPPED, IT MOVES TO WHERE THE FIELD EXISTS. Empty here means "not yet
    // rehydrated", exactly as `output_notes` is treated twelve lines up (DB-165's own shape). The
    // header root is the commitment, and `Node::credit_set_bound_after_rehydrate` re-checks it against
    // the REBUILT set at ingest — so a relay that strips or appends to the set still cannot keep the
    // block id, which is the property §BA's comment below is about. A non-empty set arriving here (an
    // in-process construction, or a peer that sent one) is still bound immediately.
    //
    // ⛔⛔⛔ DB-224 — AND NOW THE SET TRAVELS AGAIN, SO THE CONDITIONAL ABOVE IS A STRIP DOOR AND IS GONE.
    //
    // The DB-191 conditional existed only because the field was `#[serde(skip)]`: an empty set meant
    // "not yet rehydrated". `credit_set` now rides the wire in carriage form and is never rebuilt from a
    // pool, so an empty set under a non-empty root is a relay that STRIPPED it — refused like every other
    // stripped sidecar. `Node::credit_set_bound_after_rehydrate`, which the comment above names, never
    // existed; the bind lives here, on the bytes that arrived. Header shells keep `absent_ok`.
    // §22: the credit set is SEALED — its root binds the sealed bytes WHOLE, and a present set has exactly one width.
    if crate::block::credit_set_present(&block.credit_set) && block.credit_set.len() != crate::block::CREDIT_SET_SEALED_BYTES {
        return Err(ConsensusError::CreditSetNotCarriage);
    }
    if !bound(&block.credit_set, h.credit_set_root) {
        return Err(ConsensusError::CreditSetRootMismatch);
    }
    // The carriage + subject rule reads the frames, so it runs where the key is held: here for a body beside its key
    // (the producer's own, a carried body), and at the fold for every other receiver (`Node::opened_credit_objects`).
    credit_set_is_carried_with_its_subjects(
        block,
        crate::block::credit_seal_key(&block.header, block.cover_key.as_ref()).as_ref(),
        absent_ok,
    )?;
    // The directory sidecar (@username + group registrations) binds identically: a stripped or
    // swapped registration set is a DIFFERENT block, never a quietly divergent directory across
    // nodes. Same fail-closed-on-the-bad-block rule; the DAG never halts on it.
    if !bound_padded(&block.dir_set, h.dir_set_root) {
        return Err(ConsensusError::DirSetRootMismatch);
    }
    // The letter sidecar binds identically — a stripped or swapped letter-commitment set is a DIFFERENT
    // block — AND, when carried, must wear the CONSTANT cover-padded shape so real mail volume never
    // shows on the wire and every node's letter-accumulator fold consumes identical bytes. EMPTY is the
    // anchor-class marker (genesis / DSYNC anchors / pre-carrier fixtures), the exact precedent
    // `NfBlockProof`'s empty carrier set: a producing node ALWAYS seals the full cover shape, and an
    // empty carry folds nothing (`apply_letter_set` no-ops), so it can never desync the accumulator.
    let letter_want = crate::letter::LETTER_CMS_PER_BLOCK * 32;
    if !block.letter_set.is_empty() && block.letter_set.len() != letter_want {
        return Err(ConsensusError::LetterSetBadShape {
            got: block.letter_set.len(),
            want: letter_want,
        });
    }
    if !bound(&block.letter_set, h.letter_set_root) {
        return Err(ConsensusError::LetterSetRootMismatch);
    }
    // ⭐ PRIVATE SHARDING §2.2: stripped or swapped evidence is a different block. Its content is judged at the fold.
    if !bound(&block.tag_evidence, h.tag_evidence_root) {
        return Err(ConsensusError::TagEvidenceRootMismatch);
    }
    Ok(())
}

/// ⭐⭐⭐ DB-224 — THE CREDIT SET'S TWO BLOCK-VALIDITY RULES, now that it travels.
///
/// 1. **Carriage form.** Every entry must be its own `chain_object::carriage_of`: a framed object of a
///    known class whose note fields are 64-byte references, never payloads. A real payload on the block
///    wire is the only secret input of `cover::block_cover_secret` (DB-165), so this is what makes "no
///    payload byte rides a block" a property of the CHAIN rather than of a producer's courtesy.
/// 2. **The subject rule.** Every `(cm, slot)` an entry names must be a slot of THIS block's own
///    constant-width note carrier. Objects travel, so without it a producer could apply a valid peg-in's
///    ledger transition on every node (its deposit id burned) while leaving the minted note out of the
///    block. The producer seals the set through the same predicate, so an honest block always passes and
///    chain progress is never gated on it; a block that fails is refused alone.
///
/// An empty set is trivially well-formed (and is what a header shell carries). On the WHOLE-BODY door
/// (`absent_ok == false`) a set that names a note needs the carrier that commits it: a missing or malformed
/// carrier commits nothing, so it is refused as a subject failure — explicitly, never by reading an absent
/// carrier as an empty one (that door refuses a wrong-width carrier before it gets here anyway).
///
/// ⛔ ON THE REDUCED-CARRIER DOOR (`absent_ok`), AN ABSENT CARRIER SKIPS ONLY THE SUBJECT RULE. The blocks
/// that door admits — a DSYNC bundle's tip and fold-carry, descent shells — deliberately ship without
/// their note carrier (`build_sync_bundle`, `header_shell`), and their credit set is used for ONE thing:
/// justifying notes at `graft_admitted_notes`, byte-exactly against the note in hand, which is its own
/// subject. They never reach the object APPLY: `apply_chain_objects_of` runs only for blocks the relay
/// grafted through `validate_structural` (this rule, whole body, carrier present), a pre-verified whole
/// healed body, and the producer's own block (sealed through the same predicate). The CARRIAGE rule —
/// no payload byte — holds on every door: a carried block crossed the wire too.
/// Bounded: `credit_set_iter` refuses more than `BLOCK_FIXED_TX_COUNT` entries, `is_carriage` refuses an
/// entry over `MAX_CARRIAGE_ENTRY_BYTES` before decoding it; the subject check reads the carrier's fixed
/// 256 slots once.
/// DIGITAL-CASH-PRIVACY-REVIEWED: a verdict only — nothing is logged, and every value compared is one of
/// the block's own public commitments.
pub fn credit_set_is_carried_with_its_subjects(
    block: &Block,
    key: Option<&crate::cover::CoverKey>,
    absent_ok: bool,
) -> Result<(), ConsensusError> {
    if !crate::block::credit_set_present(&block.credit_set) {
        return Ok(());
    }
    // §22: a sealed set this caller holds no key for is judged where the key is (the fold); nothing is admitted by it here.
    let Some(plain) = crate::block::credit_set_open(&block.credit_set, key) else {
        return if key.is_some() { Err(ConsensusError::CreditSetNotCarriage) } else { Ok(()) };
    };
    if crate::block::sidecar_real_len(&plain) == 0 {
        return Ok(());
    }
    let Some(frames) = crate::block::credit_set_iter_plain(&plain) else {
        return Err(ConsensusError::CreditSetNotCarriage);
    };
    // §22b: a wide reference resolves against the bytes beside the body; a body that names bytes it does not hold is
    // INCOMPLETE — refused as a body at the door (the honest envelope always carries them), waited for at the fold.
    let mut entries: Vec<Vec<u8>> = Vec::with_capacity(frames.len());
    for f in frames {
        match crate::block::wide_ref_hash(&f) {
            Some(h) => match block.wide_objects.iter().find(|w| crate::block::wide_carriage_hash(w) == h) {
                // an inline-sized object dressed as a reference is a second encoding of one object (§BA): refused
                Some(w) if w.len() > crate::block::CREDIT_INLINE_MAX => entries.push(w.clone()),
                Some(_) => return Err(ConsensusError::CreditSetNotCarriage),
                None => return Err(ConsensusError::CreditSetWideMissing),
            },
            // a wide object riding inline is the second encoding the other way round: refused
            None if f.len() > crate::block::CREDIT_INLINE_MAX => return Err(ConsensusError::CreditSetNotCarriage),
            None => entries.push(f),
        }
    }
    let mut named: Vec<[u8; 32]> = Vec::new();
    for e in &entries {
        // §SIMMEM G13b: a bond-lane-only object in the credit lane is a second encoding of one object (it applies nothing
        // here) — refused, the producer's `carriage_carried_against` reading the same predicate.
        if !crate::chain_object::is_carriage(e) || crate::chain_object::rides_the_bond_lane_alone(e) {
            return Err(ConsensusError::CreditSetNotCarriage);
        }
        let Some(refs) = crate::chain_object::carriage_note_refs(e) else {
            return Err(ConsensusError::CreditSetNotCarriage);
        };
        named.extend(refs.iter().map(|(_cm, slot)| *slot));
    }
    if named.is_empty() {
        return Ok(()); // only note-free objects: nothing for the carrier to commit
    }
    if absent_ok && block.note_commitments.is_empty() {
        return Ok(()); // a reduced body: its set justifies notes byte-exactly and applies no object (above)
    }
    let Some(carrier) = crate::cover::BlockNoteCommitments::from_bytes(&block.note_commitments) else {
        return Err(ConsensusError::CreditObjectWithoutSubject);
    };
    let committed: std::collections::BTreeSet<[u8; 32]> =
        (0..crate::cover::BLOCK_FIXED_NOTE_COUNT).filter_map(|i| carrier.slot(i)).collect();
    if named.iter().all(|slot| committed.contains(slot)) {
        Ok(())
    } else {
        Err(ConsensusError::CreditObjectWithoutSubject)
    }
}

/// The WHOLE-BODY arm of [`body_commitments_admit`]: EVERY part must reproduce its header
/// commitment, absent or not. This is what the gossip door has always run — a block that arrives by
/// gossip carries its whole body by construction, so an empty part there is a claim like any other
/// and `blake3("")` is its real, checkable value. Behaviour is byte-identical to the rules that used
/// to sit inline in [`validate_structural`], in the same order, returning the same errors.
pub fn validate_full_body_commitments(block: &Block) -> Result<(), ConsensusError> {
    body_commitments_admit(block, false)
}

/// The REDUCED-CARRIER arm of [`body_commitments_admit`] — run by
/// [`crate::node::Node::header_door_admits`], the ONE site every non-gossip block placement asks for
/// its verdict, so a body that does not match its header commitment is refused at EVERY door and not
/// only at the gossip one. An ABSENT part is admissible here and only here: a shell, a fold-carry
/// block and a DSYNC bundle block are objects this chain deliberately ships without their full body,
/// and an absent part applies nothing (see the `absent_ok` residual on the shared function).
pub fn validate_carried_body_commitments(block: &Block) -> Result<(), ConsensusError> {
    body_commitments_admit(block, true)
}

/// Self-contained validity — no DAG lookups; safe before parents are known. Both halves are now
/// shared with the non-gossip doors and neither lives inline here: the header rules are
/// [`validate_header_structural`], the body rules [`validate_full_body_commitments`] (whose
/// reduced-carrier twin those doors run). This function is the composition, and the gossip door's
/// behaviour is unchanged.
pub fn validate_structural(
    block: &Block,
    now_ts: u64,
    params: &ChainParams,
) -> Result<(), ConsensusError> {
    validate_header_structural(&block.header, &block.tx_ids, Some(now_ts), params)?;
    validate_full_body_commitments(block)
}

/// Context-dependent validity — parents must be present. Returns `UnknownParent` (a buffer signal,
/// not a hard reject) when a parent is missing.
pub fn validate_contextual(dag: &Dag, h: &BlockHeader) -> Result<(), ConsensusError> {
    if h.is_genesis() {
        return Ok(());
    }
    for p in &h.parents {
        if !dag.contains(p) {
            return Err(ConsensusError::UnknownParent(*p));
        }
    }
    let Some(sp) = dag.selected_parent_of(&h.parents) else { return Err(ConsensusError::NoParents) };
    let mtp = median_time_past(dag, sp);
    if h.timestamp <= mtp {
        return Err(ConsensusError::TimestampTooEarly {
            ts: h.timestamp,
            mtp,
        });
    }
    // MERGESET SHAPE BOUND: per-block validation work must be a function of the protocol shape, never of how
    // many blocks a peer chose to withhold and release together. The walk stops at the bound, so a flood costs
    // O(shape) to reject instead of O(anticone) to process.
    let bound =
        crate::params::mergeset_shape_bound(dag.params().dag_width, dag.params().ghostdag_k);
    if let Err(got) = dag.mergeset_size_within(&h.parents, &sp, bound) {
        return Err(ConsensusError::MergesetTooLarge { got, bound });
    }
    // ⛔ A-F145 RELIEF: the block's work must lie in its admitted range — the window's figure, or less by its own real wait
    let (lo, expected, _) = crate::miner::admitted_work(dag, Some(sp), h.timestamp);
    if h.work < lo || h.work > expected {
        return Err(ConsensusError::WrongWork {
            expected,
            got: h.work,
        });
    }
    Ok(())
}

/// One spend that CANONICAL ORDERING pruned as a double-spend: `block` re-spent `nullifier` that an EARLIER block
/// (in the deterministic order) already spent. Its spend — and therefore its output notes — do NOT count for the
/// effective ledger (that is how a width>1 GHOSTDAG conserves value without ever REJECTING a block: both concurrent
/// blocks graft, only the canonical-first spender is effective).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrunedSpend {
    pub block: BlockId,
    pub nullifier: [u8; 32],
}

/// DAG-NATIVE double-spend resolution (the fix for the removed longest-chain block-reject that chain-split
/// concurrent spenders). Walk `ordered` — the DETERMINISTIC [`Dag::canonical_order`] paired with each block's real
/// nullifiers — and apply FIRST-SPENDER-WINS: the first block (in canonical order) to spend a nullifier is
/// effective; ANY later block re-spending it is a conflict, returned as a [`PrunedSpend`] (its spend + outputs are
/// dropped from the effective ledger). The result is a pure function of the canonical order + the spends, so EVERY
/// node computes the identical pruned set → no split, no double-count, no block ever rejected for a concurrent
/// conflict. O(total spends in the window). ([[feedback_monerousd_not_monero]] [[feedback_no_chain_halts]]
/// [[project_trustless_nullifier_o1_design]])
pub fn resolve_nullifier_conflicts(ordered: &[(BlockId, Vec<[u8; 32]>)]) -> Vec<PrunedSpend> {
    let mut spent: HashSet<[u8; 32]> = HashSet::new();
    let mut pruned: Vec<PrunedSpend> = Vec::new();
    for (block, nfs) in ordered {
        for nf in nfs {
            // `insert` returns false iff `nf` was already present → an earlier canonical block spent it → prune.
            if !spent.insert(*nf) {
                pruned.push(PrunedSpend {
                    block: *block,
                    nullifier: *nf,
                });
            }
        }
    }
    pruned
}

/// Median of the recent selected-chain timestamps (sample length = the governance-tunable `mtp_sample_len`). It is also THE
/// CHAIN CLOCK every protocol interval that stands for a time is read against (`Node::chain_time_ms_at`; BORROWED: Bitcoin's
/// BIP113, time locks judged by median-time-past).
pub fn median_time_past(dag: &Dag, sp: BlockId) -> u64 {
    let sample_len = dag.params().mtp_sample_len;
    let mut ts: Vec<u64> = Vec::with_capacity(sample_len);
    let mut cur = Some(sp);
    while let Some(c) = cur {
        if ts.len() >= sample_len {
            break;
        }
        match dag.get(&c) {
            Some(n) => {
                ts.push(n.header.timestamp);
                cur = n.selected_parent;
                if cur.is_none() {
                    // an anchor: continue into the window it carried (v31 fold carry)
                    if let Some(w) = dag.window_below(&c) {
                        for (t, _, _) in w.iter() {
                            if ts.len() >= sample_len {
                                break;
                            }
                            ts.push(*t);
                        }
                    }
                }
            }
            None => break,
        }
    }
    if ts.is_empty() {
        return 0;
    }
    ts.sort_unstable();
    ts[ts.len() / 2]
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader, BlockId};
    use crate::hash::Hash32;

    #[test]
    fn resolve_nullifier_conflicts_first_spender_wins_and_is_order_deterministic() {
        // #152 core: first-spender (in canonical order) wins; a later block re-spending the same nullifier is
        // PRUNED. Deterministic — depends ONLY on the given canonical order, never on any receive order.
        let ba = Hash32::hash(b"blockA");
        let bb = Hash32::hash(b"blockB");
        let nf = [7u8; 32];
        let other = [9u8; 32];
        // Two blocks each spend `nf` (a conflict) + B also spends an independent `other`.
        let ordered = vec![(ba, vec![nf]), (bb, vec![nf, other])];
        let pruned = resolve_nullifier_conflicts(&ordered);
        assert_eq!(pruned.len(), 1, "exactly one conflicting spend is pruned");
        assert_eq!(
            pruned[0],
            PrunedSpend {
                block: bb,
                nullifier: nf
            },
            "the SECOND (canonical) spender of nf loses"
        );
        // The independent nf is untouched; A's spend of nf is effective (never pruned).
        assert!(
            !pruned.iter().any(|p| p.nullifier == other),
            "an independent nullifier is not a conflict"
        );
        assert!(
            !pruned.iter().any(|p| p.block == ba),
            "the first spender is never pruned"
        );
        // No conflict → nothing pruned.
        assert!(
            resolve_nullifier_conflicts(&[(ba, vec![nf]), (bb, vec![other])]).is_empty(),
            "disjoint spends: no prune"
        );
        // Reversing the canonical order flips the loser — the resolution follows the ORDER, deterministically.
        let rev = resolve_nullifier_conflicts(&[(bb, vec![nf, other]), (ba, vec![nf])]);
        assert_eq!(
            rev,
            vec![PrunedSpend {
                block: ba,
                nullifier: nf
            }],
            "reversed order → the other block's spend is pruned"
        );
    }

    // A consensus-valid block on `parents`: work = the DAA expectation over the selected parent.
}

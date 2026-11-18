// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE OBSERVABLE-SURFACE CENSUS — PRIVACY PROVEN THE WAY SOLVENCY IS PROVEN.
//!
//! [`super::value_creation`] asks every site that CREATES value three questions and refuses to let a
//! `Missing` answer go unfiled. This is its mirror for the privacy pillar: every surface an observer
//! can SEE must answer what viewing it reveals, and a new surface cannot ship unanswered.
//!
//! ⛔⛔⛔ WHY A TABLE ALONE IS NOT ENOUGH, AND THE MEASUREMENT THAT PROVES IT. 2026-09-15, building the
//! §BA/§BB note-transition aggregate: every field of it was committed, blinded and zero-knowledge —
//! and the proof's **SIZE** was 415 KB per real spend. Nothing in it revealed a value, an identity or a
//! linkage. Reading its LENGTH revealed how many spends in that block were real, which is exactly the
//! number `cover.rs` pads the served-note count to a constant to hide. A second, subtler instance
//! survived the first fix: the proof was byte-identical across spend counts but its committed SHAPE was
//! still sized from `n.next_power_of_two()`, so 8 real spends shipped 443,723 B and 256 shipped 446,551.
//!
//! ⭐ **A SURFACE LEAKS THROUGH ITS SHAPE AS READILY AS THROUGH ITS CONTENT, AND A CENSUS OF DECLARED
//! ANSWERS CANNOT SEE THAT.** So the SHAPE axis here is not declared, it is MEASURED: build blocks whose
//! real activity differs and compare, byte for byte, what an observer receives.
//!
//! THE FOUR QUESTIONS, read off the digital-cash cardinal ("viewing the chain leaks ZERO
//! value/identity/linkage/amount AND ZERO METADATA — count/volume/timing/which-item/ordering"):
//!
//! 1. **CONTENT — do the bytes carry a value, an identity or a key?** The fix is a commitment, never
//!    the witness.
//! 2. **SHAPE — does its LENGTH, COUNT or PRESENCE move with real activity?** The fix is a cover
//!    constant. ⛔ This is the one that is measured, because it is the one that hides from review.
//! 3. **LINKAGE — can two observations be tied to one note, party or session?** The fix is a
//!    per-use-derived value, never a reused one.
//! 4. **ORDERING — does position or arrival order say which item, or how many came first?** The fix is
//!    a position that is a pure function of something public, or a constant-shape schedule.
//!
//! ⛔ SCOPE. Like the rest of the harness this is an IN-PROCESS island: it proves what a peer receives
//! in the block structure, not what a global network adversary sees on the wire. Onion transport
//! timing and per-peer traffic analysis remain the live pair gate's job.

use std::collections::BTreeSet;

/// What the BYTES of a surface carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// Committed / encrypted / derived — an observer reads no value, identity or key. Names HOW.
    Sealed(&'static str),
    /// Public BY DESIGN and carrying nothing private — names what it is.
    PublicByDesign(&'static str),
    /// ⛔ NOTHING SEALS IT. Names what leaks. Must appear in [`FILED_OPEN`].
    Leaks(&'static str),
}

/// Whether the surface's LENGTH, COUNT or PRESENCE moves with real activity.
///
/// ⛔ A `Constant` claim here is checked by `an_observer_cannot_read_real_activity_off_a_blocks_shape`,
/// which builds blocks with different real activity and compares. A claim that measurement contradicts
/// is a failing test, not a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Same size on every block, whatever happened. Names the cover constant that holds it.
    Constant(&'static str),
    /// ⛔ MOVES WITH REAL ACTIVITY. Names what an observer can count. Must appear in [`FILED_OPEN`].
    TracksActivity(&'static str),
    /// §21.1 (2026-10-28) — a constant-size list whose ENTRY COUNT is the per-block delta of a set the chain publishes BY
    /// DESIGN (the validator set — user ruling 2026-10-07, THORChain-public bonds; the @username namespace), every entry
    /// a signed public act every node judges in the open. Names the public set and the ruling. Answers the shape
    /// question: the count is the public set's own, not metadata of this chain's design. An entry that is NOT a public
    /// act by design (a note, a spend, a credit of a non-public deposit) may never file here.
    PublicActs(&'static str),
}

/// Whether two observations can be tied together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    /// Fresh or per-use-derived, so two sightings cannot be joined. Names the derivation.
    Unlinkable(&'static str),
    /// ⛔ A REUSED OR STABLE VALUE joins observations. Names what links. Must appear in [`FILED_OPEN`].
    Links(&'static str),
}

/// Whether position or arrival order says which item, or how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    /// Position is a pure function of something public, or the schedule is constant-shape. Names it.
    Fixed(&'static str),
    /// ⛔ POSITION OR ORDER IS A READOUT. Names it. Must appear in [`FILED_OPEN`].
    Reveals(&'static str),
}

/// One thing an observer can see.
#[derive(Debug, Clone, Copy)]
pub struct Surface {
    /// The production field or served object this describes.
    pub name: &'static str,
    pub content: Content,
    pub shape: Shape,
    pub linkage: Linkage,
    pub ordering: Ordering,
}

impl Surface {
    /// Does this surface answer all four questions?
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !matches!(self.content, Content::Leaks(_))
            && !matches!(self.shape, Shape::TracksActivity(_))
            && !matches!(self.linkage, Linkage::Links(_))
            && !matches!(self.ordering, Ordering::Reveals(_))
    }
    /// The unanswered questions, named — what a failure prints.
    #[must_use]
    pub fn gaps(&self) -> Vec<String> {
        let mut g = Vec::new();
        if let Content::Leaks(w) = self.content {
            g.push(format!("CONTENT: {w}"));
        }
        if let Shape::TracksActivity(w) = self.shape {
            g.push(format!("SHAPE: {w}"));
        }
        // `Shape::PublicActs`: the count is a public set's delta by the user's design — no gap (§21.1).
        if let Linkage::Links(w) = self.linkage {
            g.push(format!("LINKAGE: {w}"));
        }
        if let Ordering::Reveals(w) = self.ordering {
            g.push(format!("ORDERING: {w}"));
        }
        g
    }
}

/// Surfaces knowingly OPEN, each with its kill-list section. An entry here is a debt with a name, not a
/// pass: `every_observable_surface_answers_all_four` prints it on every run.
pub const FILED_OPEN: &[&str] = &[
    // §RF-3 (2026-10-24): `Block::output_notes` (0 B on the wire since DB-165) and `Block::pow_proof` (32 B flat) left
    // this list — both answer all four, and a filing shielded their `Constant` claims from the shape probe. The leak
    // that stayed open is the SERVED record's, filed under its own name: `Serve::da_record_notes`.
    // §20.2 (2026-10-28, lane funds): `Serve::da_record_notes` LEFT this list — the record's cover bodies and fronts follow
    // the producer-drawn COVER KEY (held beside the reals, served to peers only, never on a wallet route); MEASURED
    // `s20_a_served_record_does_not_invert_to_its_real_count`: 2 reals held, the public strip reads None, the holder's
    // strip reads Some(2); the §BX recoverability measurement re-stated (holder Some(k), observer None for 1/2/7 reals).
    // §18 (2026-10-28, lane funds): `Block::cover_transition` LEFT this list — the class is RETIRED (a stated spend's 32
    // tags ride its own 16 ledger rows, chained by the tag ledger); the producer lays none, so the field is `None` on
    // every block (0 B measured quiet · quiet · busy); its deletion from the struct is the re-genesis bundle's.
    // DB-273 (C): closed by deleting the field; gated on (B).
    // §POLES (2026-10-26): `Block::oli_tags` and `PqTx::note_clues` left this list — their one LINKAGE residual (a
    // typed-in seed writing under slot 0 beside a live device) is closed by DB-329 §7i: an undecided install writes
    // nothing until a SET-arbitrated self-claim gives it its own `chg.{d}` slot.
    // DB-329: the gossiped transaction's own leaks, each invisible to the block-only census until now.
    // §19 (2026-10-28, lane funds): `PqTx::membership_tip`, `Ask::record_by_id` and `Serve::order_book_membership_bind`
    // LEFT this list — the record-naming one-step bind is retired: a send carries only its ring-anchored member leg
    // (`s19_a_send_with_only_its_member_leg_is_admitted_and_credited_on_a_peer`: the one-step tip 0 B, the wallet sends
    // none), objects carry the member leg in the tip slot (`s19_an_objects_member_leg_verifies_at_the_shared_door_…`),
    // and the wallet's spend path builds no `/note_copath` carrier, so no spend-time ask names a record.
    // DB-363 (2026-09-30): `PqTx::membership_leaf_commit` was filed here the same day it was found (recomputable from
    // public inputs) and CLOSED the same day: the commitment is now blinded by a per-send secret both proofs share.
    // DB-223 (2026-09-29): note_transition's per-spend tuple list states the real spend count the 256 fixed tx_ids
    // slots hide (mislabeled Constant once DB-165 emptied output_notes). Closed by fixed-slot padding.
    // 2026-10-27 (lane funds): `Block::member_transition` LEFT this list — on a ledger block the member list is DERIVED
    // (padding spec §12.1) and the probe measures the aggregate alone, one size (privacy-45.log). `Block::note_transition`
    // was re-filed Constant the same hour on the SAME size measurement and WITHDRAWN (F2-red-found-20261027k: the row's
    // public flags counted a spend's 30 justified tags). 2026-10-28: it LEFT this list on the CONTENT pin —
    // `rf3_the_published_ledgers_flags_do_not_count_the_blocks_real_spends` reads quiet (0, 0) · one spend (0, 0) with
    // §18's tail rows + tag ledger and §18.1's seed front (node-63/65.log).
    // §POLES (2026-10-25): bond_set, dir_set and credit_set were un-filed as CLOSED on a LENGTH measurement (all three pad
    // to 16,384 B). The recoverability axis refutes it: their entries are public length-prefixed frames ahead of a
    // `u32::MAX` sentinel, so `sidecar_real_len` — a keyless public function — recovers the real entry count from the
    // bytes alone (`a_padded_sidecar_is_measured_for_invertibility_back_to_the_real_count`). Re-filed until the
    // entries themselves stop being countable.
    // §21.1 (2026-10-28, lane funds): `Block::bond_set` and `Block::dir_set` LEFT this list — each entry is a signed
    // PUBLIC ACT every node judges in the open (a validator's bond/unbond/seat/vote/proof: the validator set is
    // consensus-public by the user's 2026-10-07 THORChain ruling; a @username registration: a published namespace), so
    // the entry count is the public set's own per-block delta, not metadata of this chain's design (`Shape::PublicActs`;
    // `s21_a_sidecars_entries_are_public_acts_judged_identically_on_a_peer`). A null-object cover would add growth or a
    // fake public act; private staking would trade accountability for privacy — refused. `credit_set` stays: a Monero
    // peg-in is not public on Monero, so its count is new metadata until the §BR constant credit/ticket count (R6).
    // §22 (2026-10-28, lane funds): `Block::credit_set` LEFT this list — the sidecar is SEALED under the block's cover key
    // (the §20.2 precedent: served to peers beside the body, never on a wallet route); the header root binds the sealed
    // bytes whole. MEASURED `a_padded_sidecar_is_measured_for_invertibility_back_to_the_real_count`: a keyless observer
    // opens None for 1/2/7 objects while the holder reads 1/2/7 — the shape §20.2 measured for `Serve::da_record_notes`.
    // §BR-5's constant ticket count (dummies attested by custody) is the follow-on that hides the BRIDGE objects' count
    // from holders too; this closure hides every class from every non-holder today, with no quorum in the loop.
    // DB-350: the asks a node sends a peer on its wallet's behalf (see the register's `Ask::` block).
    // 2026-09-30: the resting order book's maker-chosen public terms fingerprinted an LP's ladder (DEX-GRID spec).
    // LEFT 2026-10-28 (lane funds): every term is a grid value (C1–C3) AND the wallet's LADDER COVER makes the rungs'
    // ARRIVAL carry no pattern — distinct posting heights in a 32-block window, rung order ≠ arrival order, each rung
    // its own expiry epoch (`pq_ladder::LADDER_SPREAD_BLOCKS`, MEASURED by
    // `a_ladders_rungs_arrive_in_distinct_blocks_in_no_rung_order_and_expire_in_different_epochs`). No field or
    // schedule the protocol emits joins two rungs; what remains is the anonymity set at a grid point (orders resting
    // there), the same quantity as a shielded pool's size — a market property measured on the testnet, not a handout.
    // DB-365 (2026-09-30): `/book_level` serves each resting order's maker membership bind, whose tip names the RECORD
    // that holds the maker's lot note — the `PqTx::membership_tip` class on the served book. Closes with DB-223 phase C.
];

/// ⭐⭐⭐ THE REGISTER. Every field of `Block` an observer receives, with its four answers.
///
/// ⛔ ADDING A SURFACE HERE IS NOT OPTIONAL: `every_public_block_field_is_in_the_census` derives the
/// field list from `src/block.rs` itself, so a new public field fails this module until what viewing it
/// reveals is written down.
pub const SURFACES: &[Surface] = &[
    Surface {
        name: "Block::header",
        content: Content::Sealed("roots and commitments only — no note, amount, key or address"),
        // §POLES (2026-10-25): the nonce varint followed grind luck (662 vs 663 B); the grind now starts at
        // `pow::NONCE_BASE`, so every nonce is 9 B.
        shape: Shape::Constant("fixed field set; 670 B measured on quiet and busy alike (nonce ground in a 9 B band)"),
        linkage: Linkage::Unlinkable("every root is a fold over the block's own committed sets; measured by `an_observer_cannot_read_real_activity_off_a_blocks_shape` and `a_blocks_wire_carries_no_note_payload_only_its_commitments`"),
        ordering: Ordering::Fixed("field order is the struct's, identical on every block"),
    },
    Surface {
        name: "Block::tx_ids",
        content: Content::Sealed("content ids; the bodies they name are fetched obliviously"),
        shape: Shape::Constant("cover::BLOCK_FIXED_TX_COUNT — 8,192 B (256 x 32) measured on both"),
        linkage: Linkage::Unlinkable("an id is a hash of the body, which is itself sealed; no id repeats across two blocks of one producer (`no_cover_item_repeats_across_two_blocks`)"),
        ordering: Ordering::Fixed("slot order carries cover and real alike; a slot is not a rank"),
    },
    Surface {
        name: "Block::pow_proof",
        content: Content::PublicByDesign("a PoUW solution over the header — carries no user data"),
        // ⛔ MEASURED: 93,927 B on two quiet blocks and 93,926 on a busy one. See §BX.
        shape: Shape::Constant(
            "MEASURED 32 B on quiet, quiet-control AND busy blocks \
             (`an_observer_cannot_read_real_activity_off_a_blocks_shape`). The declared \"1 byte shorter on a \
             block carrying payments\" was REFUTED by measurement — an unmeasured declaration is noise \
             whichever way it points",
        ),
        linkage: Linkage::Unlinkable("bound to this header alone"),
        ordering: Ordering::Fixed("one proof per block"),
    },
    Surface {
        name: "Block::note_transition",
        content: Content::Sealed(
            "a bound aggregate plus commitments — every tuple is a spend's PUBLIC statement, never a witness",
        ),
        // ⛔ REFILED 2026-09-29 (lane-db224-carriage, read while filing DB-223's member_transition). This was
        // Constant because "that n is the one Block::output_notes already shows" — but DB-165 took output_notes off
        // the wire (0 B, pinned by `a_node_cannot_use_the_block_to_unmask_which_record_slots_are_real`), so the
        // tuple list is now the ONLY place the block states its real spend count, which the 256 fixed `tx_ids`
        // slots otherwise hide. The shape probe measures 0 B here only because its busy block pools no real spend.
        // ⛔ 2026-10-27 (lane funds, F2-red-found-20261027k): SIZE CONSTANT, CONTENT NOT — every published row carries
        // public flags `j0 j1 t0 t1` and `block_ledger_inputs` filed a spend's other 30 constant-width tags as justified
        // cells (Σt = 30 per spend) and the quiet block's seed note as a justified note (Σj = 1): the real spend count was a
        // public function of the list's content while its size stayed 28,704 B.
        // ⭐ CLOSED 2026-10-28 (lane funds, padding spec §18/§18.1) BY MEASUREMENT: a stated spend occupies 16 hidden rows
        // (its head row + 15 tail rows carrying its own tags under no bit; the tag ledger `NoteTransition::tag_agg` chains
        // them to its spend-or-decoy carrier, verified at every ledger door) and the seed note's front is a ledger cover
        // cell — the content census pin `rf3_the_published_ledgers_flags_do_not_count_the_blocks_real_spends` reads quiet
        // (Σj, Σt) = (0, 0) · one spend = (0, 0) (node-63/65.log); the decider's content census splits no column over the
        // rows (decider-57.log); the shape probe reads 28,704 · 28,704 · 28,704 B. The justified bits now serve OBJECTS
        // only (reward, credit, mint, bond, dir — the slot class filed on those surfaces).
        shape: Shape::Constant(
            "the slot ledger on every block: 128 rows × 7 wire digests = 28,672 B + one aggregate + the tag ledger's \
             aggregate, one size at every n; CONTENT measured — the public flags read (Σj, Σt) = (0, 0) quiet and busy \
             (`rf3_the_published_ledgers_flags_do_not_count_the_blocks_real_spends`, 2026-10-28): no cell, bit or count \
             of the list moves with the real spend count",
        ),
        linkage: Linkage::Unlinkable("a tuple names commitments and a nullifier, never an owner"),
        ordering: Ordering::Fixed("block spend order; a slot is not a rank"),
    },
    Surface {
        name: "Block::member_transition",
        // ⭐ DB-223 phase A (2026-09-29). Read off `Node::finish_member_transition` and `member_transition::build`.
        content: Content::Sealed(
            "a bound member-path aggregate plus one 128-B public tuple per carrier-bearing spend: the \
             transaction-scoped leaf commitment, binder = that spend's nullifier, a digest of its two output \
             commitments, and the ring root it anchored to — no leaf, path or index",
        ),
        // ⭐ CLOSED 2026-09-29 (filed open the same evening by its author, then closed when found): phase B's optional
        // carrier is RETRACTED on the wire — the pool refuses any member carrier (`MempoolError::MemberCarrierNotYet`,
        // pinned by `db223_the_pool_refuses_any_member_carrier_until_phase_c_makes_it_mandatory`), so no block
        // aggregates one and the field is absent on every block. Phase C re-opens it only with EVERY spend carrying
        // one AND the tuple list padded to fixed slots with note_transition's.
        // ⛔ REFILED 2026-10-24 (§RF-3, lane a) BY MEASUREMENT. Phase C landed (Q7: a spend without a member carrier is
        // not stated, `pending_note_transition`), so "absent on every block" was a phase-B fact; the probe called it 0 B
        // only because its busy block stated no spend. With one stated spend the probe measures 0 · 0 · 354,019 B.
        // ⭐ RE-FILED 2026-10-27 (lane funds) BY MEASUREMENT. On a ledger block the member ledger proves over the note
        // ledger's 128 published rows and its tuple list is DERIVED, never carried (padding spec §12.1
        // `ledger_member_rows`); the block carries the aggregate alone — MEASURED quiet · quiet · busy 32 · 32 · 32 B
        // (the bound seal; the real member-ledger aggregate is one size at every n, scratchpad/funds/privacy-45.log).
        shape: Shape::Constant(
            "MEASURED by `an_observer_cannot_read_real_activity_off_a_blocks_shape` (every public block field weighed on quiet and busy alike): the member ledger on every ledger block: the aggregate alone (its tuples are derived from the note ledger's \
             published rows, padding spec §12.1), one size at every n — MEASURED quiet · quiet · busy 32 · 32 · 32 B \
             (privacy-45.log, 2026-10-27)",
        ),
        linkage: Linkage::Unlinkable(
            "names commitments, a nullifier and a ring root, never an owner; the nullifier-to-outputs join it \
             allows is the transaction's own statement, already public in its gossip (PqTx::output_notes)",
        ),
        ordering: Ordering::Fixed("the producer's pool order of carrier-bearing spends; a slot is not a rank"),
    },
    Surface {
        name: "Block::cover_transition",
        // ⛔ DECLARED 2026-09-24. `every_public_block_field_is_in_the_census` derives its list from
        // `block.rs`, and this field had NO privacy answer — so nothing in the tree said what an observer
        // learns from it. Read off `note_transition::build_cover`, which is the only writer.
        content: Content::Sealed(
            "a bound aggregate plus PADDED tags: every transaction contributes exactly              `cover_tx_width()` tags, and the builder REFUSES any other width precisely because a short              set would publish that transaction's real input count. Real and decoy are indistinguishable              within a transaction by construction",
        ),
        // ⛔ NOT CONSTANT, AND SAYING SO IS THE POINT. `build_cover` returns `None` when `covers` is
        // empty, so PRESENCE alone separates a block that carried a spend from one that did not; and
        // `tags` is `covers.len() x cover_tx_width() x 32`, so its length divided by the constant tx
        // width IS the block's real TRANSACTION count. That is the same leak `Block::output_notes`
        // already files (its length over PQ_NOTE_BYTES is the real NOTE count) — one block-level
        // activity signal, now stated twice rather than once and silently.
        // ⛔ REFILED 2026-10-04 (DB-378 spec, read off `build_cover`): "Constant, measured 0 B on quiet, quiet-control
        // and busy" was VACUOUS — the probe's busy block pools no real spend, so all three weighed `None`. The code
        // says what the comment above already said: `None` when no spend was selected (presence = "zero spends"), and
        // `covers.len() × cover_tx_width() × 32` otherwise (length = the real transaction count). Constant only when
        // the transition is laid at the block's 256 slots ALWAYS, decoy transactions proven by the lane's own
        // spend-or-decoy gate — docs/DB-378-CONSTANT-SHAPE-SPEND-TRANSITION.md.
        // §RF-3 (2026-10-24): MEASURED at last — the in-process producer laid no cover transition at all (only
        // `complete_produce_job` did), so the probe read 0·0·0. With the inline path laying it and the busy spend
        // carrying a wallet-shaped spend-or-decoy carrier: 0 B quiet vs 380,820 B busy (agg 379,781 + 1,024 tag B for
        // one tx). Third always-on aggregate for DB-378 beside note (408 KB) and member (354 KB).
        // ⭐ RETIRED 2026-10-28 (lane funds, padding spec §18): the producer lays NO cover transition — a stated spend's 32
        // tags are its own 16 ledger rows (head + 15 hidden tails), chained to its spend-or-decoy carrier by the tag ledger
        // (`NoteTransition::tag_agg`, verified at every ledger door), and the fold's re-spend contest reads a spend as its
        // head row (a multi-input spend is refused at the door until the pair rows state it — DB-83's remaining half). The
        // field is `None` on every block: MEASURED 0 · 0 · 0 B (the shape probe; the busy pin's shape assertion), the
        // calibration `a_busy_block_…` asserts its absence. Its deletion from `Block` is the re-genesis bundle's.
        shape: Shape::Constant(
            "MEASURED by `an_observer_cannot_read_real_activity_off_a_blocks_shape` (every public block field weighed on quiet and busy alike): RETIRED: `None` on every block (0 B quiet and busy, MEASURED 2026-10-28) — the class's statement moved into \
             the ledger's hidden pair rows and the tag ledger; nothing of it rides the wire",
        ),
        linkage: Linkage::Unlinkable(
            "a tag is a per-spend nullifier commitment and names no owner; the per-transaction set is              width-padded, so two sightings cannot be joined through it",
        ),
        ordering: Ordering::Fixed(
            "the block's own transaction order, as the field's doc states — a slot is not a rank",
        ),
    },
    Surface {
        name: "Block::nullifier_proof",
        // ⛔ CORRECTED 2026-09-28 (DB-353, lane-db224-carriage). This read "a recursive fold over the spend set — no
        // nullifier in the clear". The field's `NfBlockProof::padded_tags` is the block's WHOLE 256-tag set in the
        // clear — its spends' tags and the producer's fill — and until DB-353 every fill tag was a blake3 output whose
        // non-zero top byte (255 in 256) told it from every real (digest-shaped) tag. The fold is one part of the field.
        content: Content::Sealed(
            "256 nullifier tags in the clear (`padded_tags`) plus the height-1 fold that proves their insertion. A tag is \
             a PRF of a spent note, or a decoy, and names no owner; since DB-353 every fill tag and every per-tx decoy \
             is DIGEST-SHAPED exactly as a real tag is (top byte zero, eight lanes below p), so its bytes do not say \
             whether it is real",
        ),
        shape: Shape::Constant("10,174 B measured on quiet and busy alike: 256 tags whatever the block's real spend count"),
        linkage: Linkage::Unlinkable("a nullifier is joined to nothing unless a door publishes it earlier; no padded tag repeats across two blocks of one producer (`no_cover_item_repeats_across_two_blocks`)"),
        ordering: Ordering::Fixed(
            "the block's own order — each spend's tags, then the fill. A party that can already name a spend's tags \
             (every node, from that transaction's gossip: DB-239) reads the boundary; one that cannot sees 256 \
             digest-shaped tags, and the fill is keyed by a secret it lacks",
        ),
    },
    Surface {
        name: "Block::note_commitments",
        content: Content::Sealed("32-byte commitments only; the ciphertext lives in the DA record (`a_blocks_wire_carries_no_note_payload_only_its_commitments`, `no_cover_item_repeats_across_two_blocks`)"),
        shape: Shape::Constant(
            "DB-165: exactly BLOCK_NOTE_COMMITMENTS_BYTES (256 x 32 = 8,192) on EVERY block. MEASURED \
             8192 / 8192 / 8192 across quiet, quiet-control and busy — the property `output_notes` \
             never had",
        ),
        linkage: Linkage::Unlinkable(
            "real slots are scattered from a stream seeded by the producer's UNPUBLISHED miner_seed, so \
             neither the slot indices nor the real/cover boundary says anything",
        ),
        ordering: Ordering::Fixed("the fixed 256-wide layout, never arrival order"),
    },
    Surface {
        name: "Block::output_notes",
        content: Content::Sealed("each note is a sealed PQ payload; the cm is a commitment"),
        // ⛔ MEASURED: 0 B quiet, 5,765 B busy. See §BX.
        shape: Shape::Constant(
            "DB-165: `#[serde(skip)]` — contributes ZERO wire bytes. MEASURED 0 B quiet / 0 B busy \
             (`a_node_cannot_use_the_block_to_unmask_which_record_slots_are_real`); it was 0 B quiet / 5,765 B \
             busy = exactly five notes, read with one division. The same notes SERVED as the record's payload are \
             `Serve::da_record_notes`, closed on the recoverability axis by §20.2 (the cover key)",
        ),
        linkage: Linkage::Unlinkable("a note's position is its leaf offset, a pure function of the block"),
        ordering: Ordering::Fixed("no shuffle — position IS the leaf offset, identical on every node"),
    },
    Surface {
        name: "Block::cover_key",
        // §20.2 (2026-10-28, lane funds): the record's COVER KEY — 32 B the producer draws per block, the one secret
        // input of `record_cover_secret` / `header_seed` beside the reals. `#[serde(skip)]` like `output_notes`: it
        // never rides the block; it travels the LedgerRecord lane beside the body (6th column), the relay carry's last
        // element and the sync bundle's tip key, to NODES only — a wallet never holds one (it reads record leaves the
        // node serves). An idle (empty) record is keyed by the one public idle key on every node instead.
        content: Content::Sealed(
            "§22 (2026-10-28): the key also rides the node-to-node GOSSIP ENVELOPE beside the block (`block::gossip_encode`, the same audience as the record lane), so a peer opens the sealed credit set at graft; the Block's own encoding — every wallet route, page and explorer — still carries none. 32 random bytes per block, drawn by the producer; viewing them reveals nothing by themselves, and they are \
             not on the block's wire — `a_quiet_blocks_cover_secret_is_not_regenerable_from_the_served_stream` asserts \
             the key's bytes are absent from the wire and the served page",
        ),
        shape: Shape::Constant(
            "`#[serde(skip)]` — contributes ZERO wire bytes on every block, MEASURED by the shape probe as the wire with \
             and without the field (quiet · quiet · busy 0 · 0 · 0 B, the run of this landing)",
        ),
        linkage: Linkage::Unlinkable("a random key names no owner, note or amount; one per block, never reused"),
        ordering: Ordering::Fixed("one value per block; nothing to order"),
    },
    Surface {
        name: "Block::wide_objects",
        // §22b (2026-10-28, lane funds): BIP152's shape — a chain object wider than `CREDIT_INLINE_MAX` (256 B) rides the
        // sealed credit set as a 40-B reference (`WIDEREF1 ‖ blake3_derive(carriage)`), so the hashed block keeps the
        // one constant 16,384-B sealed width; the referenced bytes travel node-to-node in the gossip envelope beside the
        // cover key (and in the relay carry, the block window and the sync bundle), never on a wallet route.
        content: Content::Sealed(
            "each wide object is a sealed credit carriage (the same AEAD bytes as an inline frame, under the block's \
             cover key) — an observer of the envelope holds ciphertext it cannot open without σ, and the block's wire \
             holds only its 40-B reference inside the sealed set; \
             `s22b_a_wide_object_rides_beside_the_block_and_a_stripped_forged_or_padded_envelope_changes_nothing`",
        ),
        shape: Shape::Constant(
            "`#[serde(skip)]` — contributes ZERO wire bytes, MEASURED by the shape probe with a 1-KiB object held \
             against the wire without it (0 · 0 · 0 B, the run of this landing); the sealed set the references ride is \
             the constant 16,384-B `Block::credit_set`",
        ),
        linkage: Linkage::Unlinkable(
            "an object is named only by its carriage hash inside the sealed set; the envelope keeps no sender, \
             owner or amount, and the door drops any unnamed bytes at decode (`retain_named_wide`)",
        ),
        ordering: Ordering::Fixed("the envelope carries them in sealed-set reference order, a function of the block"),
    },
    Surface {
        name: "Block::oli_tags",
        content: Content::Sealed("tags are DA-resident and secret-seeded"),
        // ⛔ REFILED 2026-09-30 (lane-db224-carriage, read while refuting padding shape (3)). "Constant 0 B" was VACUOUS:
        // the in-process busy block files no clue, so the probe weighed an empty list (UNPROVEN, never measured).
        // READ in code (`produce_template_with`, the `block.oli_tags` fill): a pair is written only for a note this
        // producer holds a key for — clue-bearing real outputs — and "Cover slots carry no tag" (the field's own doc).
        shape: Shape::Constant(
            "12,288 B (256 × 48) on every block: ledger blocks from uniform_ledger_filing, \
             non-ledger from pad_oli_tags_to_constant (blake3 XOF seeded from real notes)",
        ),
        // ⛔ DB-329: "per-use derived" held for every index USED ONCE, and one path reused an index: a back-to-back
        // send whose previous change had not settled took the SAME `chg` index (wallet `settle_pending_change`).
        // ⭐ DB-273 §15 (2026-09-27 20:2x, wallet pins GREEN in process) deleted that path: one process's concurrent
        // objects take DISTINCT anchored indices and a full floor refuses rather than shares. What still links is
        // what no seed-enumerable index scheme can close without coordination, so the row stays OPEN on it.
        // ⭐ 2026-09-30: two of the three linking paths are CLOSED in source. DB-329 §6 (lane-db224-carriage, fddf0d5):
        // a send declared dropped at the DB-97 horizon keeps its `chg` index, which only an object spending the SAME
        // input may retake, so a late landing never shares a tag. DB-329 step 3 (lane-wallet, e4822dd): every device
        // on one seed writes change under its OWN slot domain (`chg.{d}`), claimed through the marker with §7c F1's
        // ownership rule and §7d A1's single adder. What remains is the ONE named residual below; §7b's spender-side
        // ⭐ 2026-10-26 (lane b, §POLES): the residual is CLOSED in source by DB-329 §7i (9833708, 6c7175f, 9841865).
        linkage: Linkage::Unlinkable(
            "per-use derived under the install's OWN slot domain `chg.{d}`: a seed typed into a new device starts \
             Undecided and writes nothing (db329_s3_the_allocator_refuses_every_unsettled_slot) until it holds a slot — \
             with no free marker it self-claims the first absent slot, `tag1 = N_d`, so the SET admits one install per \
             slot (db329_s7e_two_undecided_installs_with_no_free_marker_never_share_an_unarbitrated_slot, \
             db329_s7i_slot_step_an_import_with_no_free_marker_self_claims_the_first_absent_slot_and_a_loser_never_adopts), \
             and a loser claims the next absent slot, never the one it lost \
             (db329_s7i_a_self_claim_loser_self_claims_the_next_absent_slot_never_needs_add). A dropped-then-landed \
             send keeps its index (DB-329 §6); one process's back-to-back sends (DB-273 §15) never shared",
        ),
        ordering: Ordering::Fixed("DA shard order, not arrival order"),
    },
    // ⛔ DB-273 (2026-09-27): this entry claimed `Sealed · Constant 0 B · Unlinkable (per-tx derived)`. The "0 B"
    // was vacuous — the in-process scenario files no wallet target — and the other two were never measured.
    // READ in code (`Node::adopt_account_targets_at`): each entry is `cm(32) ‖ bucket(32) ‖ len(2) ‖ ek(1,184)`,
    // where `bucket = blake3(domain ‖ b)` is the SAME for every payment to one wallet and `ek` is its ML-KEM key.
    // MEASURED on a real pair ([probeT1], node 09e531b0): one block adopted 3,750 B = 3 targets × 1,250 B, filed
    // under 2 distinct wallet buckets. Filed OPEN; closed by DB-273 (C) — the field, its header root and the
    // node's bucket filing deleted — which is gated on (B) (the wallet stops reading buckets: DB-276 + §7).
    Surface {
        name: "Block::account_targets",
        content: Content::Sealed("commitments; the bucket and ek are identifiers, not values"),
        shape: Shape::Constant("0 B, always (H5 / DB-273 C, 2026-10-05): consensus refuses a block carrying any (`AccountTargetsCarried`), the producer fills none (`no_block_and_no_transaction_carries_account_targets`)"),
        linkage: Linkage::Unlinkable("nothing is carried"),
        ordering: Ordering::Fixed("slot order"),
    },
    // `Block::del_set` LEFT 2026-10-03: the field was retired with the deletion model by the Z-build (2026-09-22) — a
    // public deletion set named the spent note's commitment, linking every spend to its receipt. A spend is refused by
    // its NULLIFIER now, and the nullifiers' surface is `PqTx::nullifiers` and the band transition. The row stayed
    // CLOSED for a field that did not exist until `census_universe_gaps` learned to refuse a stale row.
    Surface {
        name: "Block::bond_set",
        content: Content::PublicByDesign("validator bond weights are consensus-public by design"),
        // §RF-3 (2026-10-24): "0 B on quiet and busy alike" was a vacuous reading — no fixture carried a bond-lane
        // object. With one unbond in the busy block the probe MEASURED 0 · 0 · 6,094 B.
        shape: Shape::PublicActs(
            "MEASURED by `s21_a_sidecars_entries_are_public_acts_judged_identically_on_a_peer` and weighed by `an_observer_cannot_read_real_activity_off_a_blocks_shape`: 16,384 B on every block (§POLES); its entries are a validator's signed public acts (bonds, unbonds, seats, \
             finality votes, equivocation / theft proofs) whose effect every node serves by design — the validator set and \
             its weights (user ruling 2026-10-07: SAT-only, THORChain-public), finality, slashing — so the entry count is \
             that public set's per-block delta (§21.1; MEASURED 0 · 0 · 6,094 B with one unbond, the count the set shows)",
        ),
        linkage: Linkage::Unlinkable("a bond names a validator, never a spender"),
        ordering: Ordering::Fixed("set semantics"),
    },
    Surface {
        name: "Block::credit_set",
        content: Content::PublicByDesign(
            "DB-224: framed chain objects in CARRIAGE form — every note payload replaced by its 64-byte \
             reference cm || blake3(payload), and a block carrying anything else is refused \
             (CreditSetNotCarriage). What remains is what each object's own design already publishes: a \
             deposit id, an asset id, a price, a bonded attestation. No note ciphertext rides here — the \
             only secret input of the record cover never reaches the block wire.",
        ),
        // §POLES (2026-10-25): padded to a constant 16,384 B (`poles_bond_set_dir_set_and_credit_set_have_constant_byte_shape`),
        // but the LENGTH is not the count: the recoverability probe below recovers it from the bytes alone.
        // §22 (2026-10-28): SEALED under the block's cover key σ — `check(32) ‖ frames ‖ sentinel ‖ pad` XOR a keyed
        // XOF, one width on every block, the header root over the sealed bytes whole. The §POLES pad fixed the length;
        // the entries stayed public frames an observer could count. Now the frames exist only for a holder of σ (the
        // producer; a peer once the record lane delivered it; the fold), and the mempool's frame budget keeps every
        // block inside the one width (an over-budget object waits one block, never refused).
        shape: Shape::Constant(
            "16,384 B on every block, SEALED under the block's cover key (§22): a keyless observer opens None and its \
             frame walk reads no entry for 1/2/7 objects while the holder reads 1/2/7 — MEASURED by \
             `a_padded_sidecar_is_measured_for_invertibility_back_to_the_real_count` on the seal and by \
             `poles_bond_set_dir_set_and_credit_set_have_constant_byte_shape` on produced idle and busy blocks; a \
             carriage wider than `CREDIT_INLINE_MAX` rides inside as a 40-byte reference with its bytes beside the body \
             in the node-to-node envelope (§22b, BIP152), so the hashed block is one width with or without a wide object \
             (`s22b_a_wide_object_rides_beside_the_block_and_a_stripped_forged_or_padded_envelope_changes_nothing`)",
        ),
        linkage: Linkage::Unlinkable(
            "an object names a deposit, an asset or a price, never a spender; a credited note appears only \
             as its commitment and payload hash — the hash names that note's slot in the block's note \
             carrier (a CREDITED note's slot, never a payment's), which the subject rule needs to refuse \
             an object whose note the block does not carry",
        ),
        ordering: Ordering::Fixed("staging order, then the template's tx order; a slot is not a rank and no position names an owner"),
    },
    Surface {
        name: "Block::dir_set",
        content: Content::PublicByDesign("the on-chain directory is a published namespace"),
        // §RF-3 (2026-10-24): the same vacuous reading as bond_set; one signed @username in the busy block MEASURED
        // 0 · 0 · 6,969 B.
        shape: Shape::PublicActs(
            "MEASURED by `s21_a_sidecars_entries_are_public_acts_judged_identically_on_a_peer` and weighed by `an_observer_cannot_read_real_activity_off_a_blocks_shape`: 16,384 B on every block (§POLES); its entries are signed registrations in a PUBLISHED namespace, each an \
             opt-in public act every node applies in the open, so the entry count is the namespace's per-block delta \
             (§21.1; MEASURED 0 · 0 · 6,969 B with one sign-up, the registration the namespace then shows)",
        ),
        linkage: Linkage::Unlinkable("a directory entry names a username, never a note"),
        ordering: Ordering::Fixed("set semantics"),
    },
    Surface {
        name: "Block::letter_set",
        content: Content::Sealed("letter content is an encrypted stream"),
        shape: Shape::Constant("2,048 B on quiet and busy alike — a constant cover shape"),
        linkage: Linkage::Unlinkable("per-letter derived; no 32-B chunk repeats across two blocks of one producer (`no_cover_item_repeats_across_two_blocks`)"),
        ordering: Ordering::Fixed("constant-shape schedule"),
    },
    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    // ⭐ DB-329 — THE GOSSIPED TRANSACTION. `PqTx` is postcard-encoded WHOLE for gossip, so every field below reaches
    // every node, exactly as a block field does. Each answer is READ in code (mempool.rs's field docs, the wallet's
    // builders, the node's parsers); DB-327's `stake_notes` leak lived here while the census read only `Block`.
    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    Surface {
        name: "PqTx::id",
        content: Content::PublicByDesign("blake3(blob): the content id of bytes that are themselves sealed"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 32 B"),
        linkage: Linkage::Unlinkable("a hash of a fresh proof blob — a new value per transaction"),
        ordering: Ordering::Fixed("one scalar per transaction"),
    },
    Surface {
        name: "PqTx::blob",
        content: Content::Sealed("the zero-knowledge spend carrier over commitments — never a witness"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: a per-CLASS layout (pathless carriers, DB-74): a send's blob does not move with its amount"),
        linkage: Linkage::Unlinkable("fresh proof randomness per transaction"),
        ordering: Ordering::Fixed("one object"),
    },
    Surface {
        name: "PqTx::weight",
        content: Content::PublicByDesign("the serialized + verification weight, a function of the blob's class layout"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: per class, never per amount"),
        linkage: Linkage::Unlinkable("a class constant"),
        ordering: Ordering::Fixed("one scalar"),
    },
    Surface {
        name: "PqTx::nullifiers",
        content: Content::Sealed(
            "TX_FIXED_NULLIFIER_COUNT tags: the real nullifier (a PRF of the spent note) padded with decoys \
             `cover_tag_native(bound(tx_secret), slot)`",
        ),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: TX_FIXED_NULLIFIER_COUNT × 32 B on every spend"),
        linkage: Linkage::Unlinkable("a nullifier is joined to nothing unless a door publishes it earlier (DB-327 closed the one that did)"),
        // READ, and the reason this is NOT filed: the real nullifier IS at position 0 (the wallet's
        // `aligned_padded_tags` pushes it first), but the spend's own statement already names it publicly — the
        // validity carrier welds `tx.nullifiers[0]` (rpc_http ~1871) and the block's note-transition tuple states it
        // (`Block::note_transition`). Position adds no readout the statement does not already publish; the decoys pad
        // the accumulator's width, not the spend's identity.
        ordering: Ordering::Fixed(
            "the real nullifier sits at slot 0, and the spend's validity statement names that same nullifier \
             publicly (carrier weld, block tuple), so the slot reveals nothing the statement does not",
        ),
    },
    Surface {
        name: "PqTx::pow_stamp",
        content: Content::PublicByDesign("the #72 anti-spam stamp nonce"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 8 B"),
        linkage: Linkage::Unlinkable("ground per transaction"),
        ordering: Ordering::Fixed("one scalar"),
    },
    Surface {
        name: "PqTx::note_clues",
        content: Content::Sealed(
            "per-output OLI records `cm ‖ len ‖ clue`: a salted locator tag from the recipient's (or the wallet's \
             own) locator secret, byte-indistinguishable from a detection clue",
        ),
        shape: Shape::Constant("one record per output of the class (a send: recipient + change, a zero change on `void`)"),
        linkage: Linkage::Unlinkable(
            "the tag is per-use derived under the install's own `chg.{d}` slot, as Block::oli_tags one hop earlier: a \
             typed-in seed writes nothing while Undecided (db329_s3_the_allocator_refuses_every_unsettled_slot) and \
             takes a SET-arbitrated slot of its own \
             (db329_s7e_two_undecided_installs_with_no_free_marker_never_share_an_unarbitrated_slot), so no two \
             installs gossip one tag (DB-329 §7i)",
        ),
        ordering: Ordering::Fixed("output order (recipient, change): a slot, not a rank"),
    },
    Surface {
        name: "PqTx::account_targets",
        content: Content::Sealed("per output `cm ‖ bucket_id ‖ ek_len ‖ ek`: the note's owner-bucket filing"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 0 B, always: the pool refuses a transaction carrying any (`MempoolError::AccountTargetsCarried`); the wallet sends none (DB-273 L5)"),
        linkage: Linkage::Unlinkable("nothing is carried"),
        ordering: Ordering::Fixed("output order"),
    },
    Surface {
        name: "PqTx::output_notes",
        content: Content::Sealed("1,153-B sealed notes (cm ‖ ML-KEM ct ‖ enc_amount ‖ view tag): the amount is encrypted"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 2 × 1,153 B on a send (recipient + change), a class constant"),
        linkage: Linkage::Unlinkable("a fresh ML-KEM encapsulation per note; change is a fresh note, never a re-issued ciphertext (DB-273 D0)"),
        ordering: Ordering::Fixed(
            "recipient then change; a spend later reveals only a nullifier, never a commitment, so the slot joins nothing",
        ),
    },
    // ⭐ DB-327 / DB-330 — CLOSED 2026-09-27 19:4x, read in the live tree. The field (`cm ‖ amount ‖ future nullifier`)
    // is refused at BOTH doors a transaction can enter a node by, so no honest node pools, relays or produces one:
    // the submit door answers 422 STAKE_PAUSED before any proof (`db327_a_stake_bearing_submit_is_refused_at_the_door_
    // before_any_proof`), and `Mempool::accept_inner` — where the submit arm, gossip and re-admission all end — refuses
    // a new id with `StakeFormatRetired` (`db330_the_pool_refuses_a_stake_bearing_tx_and_accepts_a_plain_one`); a known
    // id's differing bytes are refused by the envelope arm. The wallet has no encoder for it (DB-327's census pin).
    // A hostile client's own bytes reach at most its direct peers, which refuse them and relay nothing.
    // Re-opened only by DB-237's private stake, which carries no such field.
    Surface {
        name: "PqTx::stake_notes",
        content: Content::Sealed(
            "always empty on every honest path: the wallet builds no stake record (DB-327), the submit door refuses \
             one with 422 STAKE_PAUSED, and the pool door refuses any transaction carrying one (StakeFormatRetired, \
             DB-330) — so no node pools, relays or produces the retired `cm ‖ amount ‖ nullifier` format",
        ),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 0 B on every transaction a node admits; a non-empty field is refused at both doors"),
        linkage: Linkage::Unlinkable("no record is ever admitted, so no nullifier is published ahead of its spend"),
        ordering: Ordering::Fixed("empty"),
    },
    Surface {
        name: "PqTx::bond_notes",
        content: Content::PublicByDesign("`vid ‖ W`: a validator's public identity and bonded weight — consensus weights are public"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 40 B on a bond (a public act by design), empty otherwise"),
        linkage: Linkage::Unlinkable("a bond names a validator, never a spender (Block::bond_set's answer)"),
        ordering: Ordering::Fixed("one record"),
    },
    Surface {
        name: "PqTx::nullifier_witnesses",
        content: Content::PublicByDesign(
            "compressed sparse-view copaths for the tags already in `nullifiers` — data any holder of the view derives \
             and every node serves (/get_nf_copath)",
        ),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: TX_FIXED_NULLIFIER_COUNT copaths"),
        linkage: Linkage::Unlinkable("keyed by the tags already public in `nullifiers`"),
        ordering: Ordering::Fixed("aligned one-to-one with `nullifiers`; its position readout is filed there"),
    },
    Surface {
        name: "PqTx::nullifier_absence",
        content: Content::Sealed("one constant-size fold proof per tag against A_tip — no copath, no held tree"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: TX_FIXED_NULLIFIER_COUNT constant-size proofs"),
        linkage: Linkage::Unlinkable("a proof per public tag"),
        ordering: Ordering::Fixed("aligned with `nullifiers`; filed there"),
    },
    Surface {
        name: "PqTx::membership_carrier",
        content: Content::Sealed("the O(1) note-membership proof over the tx-scoped leaf commitment — never the leaf"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 9,349 B measured flat over 24 folds (mempool.rs)"),
        linkage: Linkage::Unlinkable("bound to `membership_leaf_commit`, which is scoped to this transaction"),
        ordering: Ordering::Fixed("one object"),
    },
    Surface {
        name: "PqTx::membership_leaf_commit",
        content: Content::Sealed("note_leaf_commitment(leaf, tx_binder, blind): never the leaf written at receive"),
        shape: Shape::Constant("32 B"),
        // ⛔ DB-363 REFILED 2026-09-30 (found reading phase C's tuple): "scoped to this tx" answered a different question
        // (two spends of one note). Both inputs of `P(leaf, tx_binder)` were public — the binder is the nullifier this
        // tx states, the leaf is in the spend tree — so the commitment was recomputable: MEASURED RED (643 of 1,024
        // leaves singled out). CLOSED the same day: the commitment is `P(P(leaf, tx_binder), r)` for a per-send `r`
        // the wallet draws from the OS CSPRNG (`fresh_lc_blind`) and shares only between the two proofs.
        linkage: Linkage::Unlinkable(
            "blinded by a per-send secret only the two proofs share (DB-363): no public input recomputes it. MEASURED by \
             `db363_a_spends_public_leaf_commit_never_singles_out_its_input_among_the_chains_leaves` — the unblinded \
             join names exactly the spent leaf (the attack is armed), the blinded commitment singles out 0 of 1,024 \
             under that join and under a guessed blinding",
        ),
        ordering: Ordering::Fixed("one scalar"),
    },
    Surface {
        name: "PqTx::member_carrier",
        // ⭐ DB-223 phase B (2026-09-29). The wallet's member witness book builds it from public bytes only.
        content: Content::Sealed(
            "the member-path proof over the spent note's depth-64 path to a ring root; its public side is \
             PqTx::member_tuple — never the leaf, path or index",
        ),
        // ⭐ CLOSED 2026-09-29 (filed open by its author, then closed when found): an OPTIONAL carrier told a wallet that
        // held a ready path from a fresh, restarted or restored one. Retracted on the wire: the pool refuses ANY present
        // carrier or tuple before any verify (`MempoolError::MemberCarrierNotYet`), and the wallet attaches none. Phase C
        // makes it MANDATORY for every spend at once — never optional again.
        shape: Shape::Constant(
            "MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: absent on every transaction: the pool refuses a present member carrier until phase C makes it \
             mandatory for every spend",
        ),
        linkage: Linkage::Unlinkable("bound to its member_tuple, which is cross-bound to this transaction's own spend"),
        ordering: Ordering::Fixed("one object"),
    },
    Surface {
        name: "PqTx::member_tuple",
        content: Content::Sealed(
            "128 B: the tx-scoped leaf commitment (already PqTx::membership_leaf_commit), binder = this tx's \
             nullifier (already its spend statement), a digest of its two output commitments (already \
             PqTx::output_notes), and the ring anchor",
        ),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 128 B whenever present; its presence is PqTx::member_carrier's, filed there"),
        // DB-363: absent on every transaction today (the pool refuses it). It carries the SAME commitment as
        // PqTx::membership_leaf_commit — blinded since 2026-09-30 (`prove_member_path_carrier` takes the spend's
        // blinding), so phase C, which makes it mandatory, ships with the closed form.
        linkage: Linkage::Unlinkable(
            "the anchor is the ring root at SEND time — the wallet polls the stream right before it proves — so it \
             is the root every spend submitted at that fold step names, and a wallet's last-sync point never rides it; \
             its leaf commitment is the blinded DB-363 value (the spend's own), absent from the wire today",
        ),
        ordering: Ordering::Fixed("one tuple"),
    },
    Surface {
        name: "PqTx::membership_tip",
        content: Content::PublicByDesign("`tip_prev ‖ tip_root ‖ tip_acc ‖ named_record(u64)`: public chain coordinates"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: the one-step layout's fixed width"),
        // ⛔ READ (node `verify_membership_carrier_one_step` / the tip parse ~31179): `named_record` is the RECORD
        // holding the spent note, and `tip_root` is that record's root.
        // ⭐ CLOSED 2026-10-28 (§19, lane funds) BY MEASUREMENT: the wallet sends NO one-step bind (lib.rs: the send
        // path's `membership_carrier_hex` / `membership_tip_hex` are empty; `membership_bind_for` builds the member leg
        // for objects), the submit door admits a spend on its member leg alone and a peer credits it
        // (`s19_a_send_with_only_its_member_leg_is_admitted_and_credited_on_a_peer`: tip 0 B). On an object the slot
        // carries the member TUPLE, whose anchor is the NEWEST ring root the stream named — a fold-step coordinate every
        // node holds, saying nothing of the note's age or record.
        linkage: Linkage::Unlinkable(
            "empty on a send (the member leg is the evidence); on an object the member tuple — binder, blinded leaf \
             commit, zero outputs, the newest ring root — names no record and no receive",
        ),
        ordering: Ordering::Fixed("one tuple"),
    },
    Surface {
        name: "PqTx::membership_folded_through",
        // READ: node.rs has NO reader of this field (rpc_http parses it with `unwrap_or(0)`, only envelope tests
        // touch it). The wallet used to fill it with the spent note's RECORD ADDRESS (`folded_through = note_seq`) —
        // the same join as membership_tip, stated twice — and since DB-329 sends none, so every wallet tx gossips 0.
        // A field no verifier reads is vestigial: deleting it from `PqTx` is the node lanes' clean-up.
        content: Content::PublicByDesign("an ordinal no verifier reads; the wallet sends none, so it gossips 0"),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: 8 B"),
        linkage: Linkage::Unlinkable("a constant 0 from the wallet (DB-329); it named the input's record until then"),
        ordering: Ordering::Fixed("one scalar"),
    },
    Surface {
        name: "PqTx::spend_or_decoy",
        content: Content::Sealed(
            "a zero-knowledge carrier over the tag set; its witness (cover secret, note keys, the REAL-INPUT COUNT) is \
             absent by construction (selector as a witness column, blinded trace)",
        ),
        shape: Shape::Constant("MEASURED by `every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount`: the same shape whatever the real count (its own doc)"),
        linkage: Linkage::Unlinkable("fresh proof randomness"),
        ordering: Ordering::Fixed("one object"),
    },
    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    // ⭐ DB-350 — THE ASK A NODE SENDS A PEER ON ITS WALLET'S BEHALF. A which-item query is a surface exactly like a
    // block field: the peer that receives it VIEWS it. This register read only what a node PUBLISHES (`Block`, `PqTx`),
    // and the by-commitment record ask (kind 3) lived outside that universe, naming a wallet's note to a peer. Every
    // `want_*` door a wallet-facing RPC handler calls raises one of the asks below; `every_wallet_facing_want_door_is_
    // in_the_census` derives the doors from rpc_http.rs, so a new one cannot ship unanswered. Each answer is READ in
    // code (the door, the builder in node_runtime.rs's drain, the serve arm) and the kind-3 / kind-2 answers are
    // MEASURED by `db350_cm_ask_privacy_tests` (what the peer received, two parties).
    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    Surface {
        name: "Ask::record_by_commitment",
        content: Content::PublicByDesign(
            "RETIRED (DB-350): no node builds it. The wallet posts no by-commitment want, and the route, the want set and \
             the builder are deleted at source. A stale peer's kind-3 bytes are answered with an empty frame and counted \
             (`[cm-ask-in]`); the tag stays reserved, so those bytes are never read as another kind",
        ),
        shape: Shape::Constant("MEASURED by `db350_a_stale_by_commitment_ask_is_answered_with_nothing_and_its_route_is_gone` and `db350_a_wallets_membership_miss_never_puts_its_commitment_on_the_wire`: 0 B: never sent (MEASURED: no received byte string carries the owned commitment)"),
        linkage: Linkage::Unlinkable("nothing is sent"),
        ordering: Ordering::Fixed("nothing is sent"),
    },
    Surface {
        name: "Ask::record_by_id",
        content: Content::PublicByDesign(
            "kind 2, `[2] ‖ u64 LE …`: canonical record ADDRESSES — block-derived chain coordinates every node holds — \
             never a commitment, slot, key or amount (MEASURED: the owned commitment rides no ask in any spelling)",
        ),
        shape: Shape::Constant(
            "1 + 8·RECORD_ASK_WIDTH B, always (H5 / DB-350, 2026-10-05): the real wants ride among decoys — records the \
             asker itself holds, chosen by a PRF keyed with its process secret — in a keyed order; the width is the number of \
             whole records one answer carries, so every id is answered (`the_record_ask_has_one_width_whatever_the_node_owes_and_a_decoy_answer_changes_nothing`)",
        ),
        // ⭐ CLOSED 2026-10-28 (§19): the wallet's spend path builds no `/note_copath` carrier, so no spend-time miss
        // asks for the record holding the note about to be spent; every by-id ask is the record lane's owed-record pull
        // (`Node::owed_record_ids`, the same for every held block on every node) among the DB-350 decoys.
        linkage: Linkage::Unlinkable(
            "the record lane's owed-record pulls among decoys — a function of the blocks a node holds, never of a note it \
             is about to spend (the spend path builds no record-naming carrier since §19). Before: \
             The wallet's batched note fetch, DB-228, reaches the same door with its located records among keyed cover \
             drawn from the index's real entries, so those ride k-anonymous. MEASURED: across two notes of ONE record \
             the asks are byte-identical, and across records they differ only in the 8-byte address \
             (`db350_the_ask_names_the_record_never_which_of_its_notes_the_wallet_owns`)",
        ),
        ordering: Ordering::Fixed(
            "one canonical ascending set, each id once (DB-350): the held-block wants and the resolver-miss wants used to \
             ride as two runs, so a position past the first run said a READ had missed that record — MEASURED closed by \
             `db350_every_by_id_ask_is_one_ascending_set`",
        ),
    },
    Surface {
        name: "Ask::record_by_ordinal",
        content: Content::PublicByDesign(
            "kind 0, `[0] ‖ u64 LE …`: dense record ORDINALS — a client's paging window (`/get_pq_notes`: its cursor and \
             the next TX_REQ_FIXED_COUNT − 1) and this node's own resume holes; never a commitment, slot, key or amount",
        ),
        shape: Shape::Constant(
            "MEASURED by `db350_the_missed_record_still_arrives_by_its_public_address` (the ordinal window names no item a wallet owns): at most TX_REQ_FIXED_COUNT ordinals, n = this node's holes inside a fixed window — a function of its sync \
             state, never of a wallet's notes or payments",
        ),
        linkage: Linkage::Unlinkable(
            "a sequential cursor over EVERY record: every scanning client walks the same positions, so a window names \
             no item a wallet owns",
        ),
        ordering: Ordering::Fixed("ascending ordinals"),
    },
    Surface {
        name: "Ask::account_bucket",
        content: Content::Sealed(
            "`BucketReq`: TX_REQ_FIXED_COUNT × 32 B — the wanted account-bucket ids padded with decoys \
             `blake3(\"MUSD-bucket-cover-v1\" ‖ node DA secret ‖ i)`",
        ),
        shape: Shape::Constant("0 B: never sent — `/account_bucket` is RETIRED and records no want, the wallet asks none (DB-273 L5 / C)"),
        linkage: Linkage::Unlinkable("nothing is sent"),
        ordering: Ordering::Fixed(
            "one canonical ascending set (DB-356): the real wants and the decoys are sorted together, so a slot's \
             position is a function of the id's value alone — MEASURED by \
             `db356_the_bucket_ask_is_one_ascending_set_so_no_slot_says_which_want_is_real` (the highest real want now \
             sits LAST; before, every real want sat in a leading slot)",
        ),
    },
    // ⛔ FILED OPEN 2026-09-30 (found answering the user's IonSwap-vs-Uniswap question; docs/DEX-GRID-ENFORCEMENT-SPEC.md).
    // READ: `order_book.rs` claims "one public grid, one fixed lot", but `OrderBook::post` refuses only lot/pay_b == 0,
    // `level()` is a 2× price BAND, and the wallet `LadderPlan`'s mid/step/lot/expiry are free fields. The terms are
    // public in every maker half, in the served book and in the settled fill.
    Surface {
        name: "Serve::order_book_terms",
        content: Content::PublicByDesign(
            "each resting order's `OrderTerms` (lot, pay_b, assets, expires_at_height): a taker must read the price to \
             fill it",
        ),
        shape: Shape::Constant("one fixed-width terms record per order; the served level page is TX_REQ_FIXED_COUNT slots"),
        // NARROWED 2026-09-30 (DEX-GRID interim LANDED): every term is now a protocol grid value — price and lot on the
        // mantissa grid, expiry on the epoch — enforced at the post door AND the settlement engine every node runs at
        // graft (`order_book::on_grid`), and the wallet produces only grid values. STILL OPEN, honestly: a grid point
        // holds about one order (C4), so the PATTERN of grid points one LP chooses can still link its ladder. The claim
        // is exactly "no distinctive terms", and invisible orders close it.
        // CLOSED 2026-10-28 (lane funds, THE LADDER COVER): the step is the protocol grid and the lot a governance
        // constant, so a ladder's only free terms were its mid, its width and its arrival. The wallet now posts the
        // nearest rung a side at once (the best bid/ask ARE the public mid of any book) and every further rung at its
        // own height in a 32-block window, in a seeded order independent of the rung order, each with its own expiry
        // epoch — MEASURED over 64 ladders by
        // `a_ladders_rungs_arrive_in_distinct_blocks_in_no_rung_order_and_expire_in_different_epochs`. Nothing the
        // chain, the served book or a fill carries names a ladder; what remains is the anonymity set at a grid point.
        linkage: Linkage::Unlinkable(
            "every term is a protocol grid value; a rung's arrival height and expiry epoch are drawn per rung from the \
             ladder's secret cover seed (`pq_ladder::LADDER_SPREAD_BLOCKS`), so neither the terms nor the schedule \
             joins two rungs — the residual is the anonymity set at (pair, grid point), a market quantity; MEASURED by \
             `a_ladders_rungs_arrive_in_distinct_blocks_in_no_rung_order_and_expire_in_different_epochs`",
        ),
        ordering: Ordering::Fixed("per (pair, band), book order; a slot is not a rank"),
    },
    Surface {
        name: "Serve::order_book_membership_bind",
        // ⛔ FILED 2026-09-30 (lane-db224-carriage, DB-365, read while answering lane-wallet's cross-node fill finding).
        // READ in code: `/book_level` (rpc_http.rs) hex-serves each resting order's `membership_carrier` and
        // `membership_tip`; the tip is `GENESIS_ACC ‖ tip_prev ‖ tip_root ‖ acc ‖ record u64` (the one-step bind the
        // DB-150 helper builds), so the served book names the RECORD that holds each maker's lot note. The wallet reads it
        // to build its fill (lib.rs `maker_membership_carrier_hex`), and the fill object carries it on chain at settle.
        content: Content::PublicByDesign(
            "a recursive membership proof over public per-block anchors, bound to the order's published leaf_commit — \
             no amount, key or owner",
        ),
        shape: Shape::Constant("one bind per resting order, served in the level's constant-shape page"),
        // ⭐ CLOSED 2026-10-28 (§19): the wallet's order post carries the maker's MEMBER LEG in the bind slot
        // (`membership_bind_for` → `MemberWitnessBook::carrier_for` under zero outputs, anchored at the newest ring
        // root), judged by `bond_membership_verdict`'s record-free arm at the book and at the fill door
        // (`s19_an_objects_member_leg_verifies_at_the_shared_door_and_every_tamper_is_refused`, MEASURED).
        linkage: Linkage::Unlinkable(
            "the served bind is the maker's member tuple — binder, blinded leaf commit, zero outputs, the newest ring \
             root — a fold-step coordinate every node holds; it names no record and joins the order to no receive; \
             MEASURED by `s19_an_objects_member_leg_verifies_at_the_shared_door_and_every_tamper_is_refused`",
        ),
        ordering: Ordering::Fixed("per (pair, band), book order; a slot is not a rank"),
    },
    // FILED 2026-10-24 (§RF-3) on the recoverability axis (§BX): `Node::da_record_notes` served
    // `assemble_fixed_note_payload_det(reals, addr)`, a keyless public function of the reals, so any fetcher stripped the
    // real count (MEASURED 1/2/7 → 1/2/7). CLOSED 2026-10-28 (§20.2, lane funds): the cover bodies are
    // `cover_note_det(record_cover_secret(addr, key), slot)` and the fronts follow `header_seed(reals, key)`, `key` the
    // producer's fresh draw held beside the reals (`Block::cover_key` in process, the record lane / page / checkpoint row
    // between nodes) and NEVER on a wallet route. MEASURED `s20_a_served_record_does_not_invert_to_its_real_count`
    // (node-91.log): the public strip reads None, the holder's strip reads the exact reals; the §BX measurement re-stated
    // (holder Some(k), observer None for 1/2/7).
    Surface {
        name: "Serve::da_record_notes",
        content: Content::Sealed("each unit is a sealed PQ note payload; cover units are value-0 notes keyed on the record's cover key"),
        shape: Shape::Constant(
            "256 × PQ_NOTE_BYTES on every record, and NOT invertible without the record's cover key: the public strip \
             (the idle key) recovers nothing (MEASURED None for 1/2/7 reals by \
             `a_constant_shape_is_measured_for_invertibility_back_to_the_real_count`; None on a produced block by \
             `s20_a_served_record_does_not_invert_to_its_real_count`); the holder's key recovers the exact reals",
        ),
        linkage: Linkage::Unlinkable("each note is its own fresh ML-KEM encapsulation; nothing repeats across records"),
        ordering: Ordering::Fixed(
            "reals first, then the keyed cover; without the key no unit is testable, so position says nothing \
             (`strip_fixed_note_payload` under the public key: None)",
        ),
    },
];

/// The public fields of `pub struct Block`, read out of the source so the census cannot drift from
/// the struct. Mirrors `value_creation::classes_that_carry_notes`.
pub fn block_public_fields(src: &str) -> BTreeSet<String> {
    struct_public_fields(src, "pub struct Block {")
}

/// ⭐ DB-329 — the public fields of `pub struct PqTx` (src/mempool.rs). A transaction is postcard-encoded WHOLE for
/// gossip, so every one of these reaches every node exactly as a block field does; the census that read only
/// `Block` could not see a leak that rode the transaction (DB-327's `stake_notes`: amount + future nullifier).
pub fn pqtx_public_fields(src: &str) -> BTreeSet<String> {
    struct_public_fields(src, "pub struct PqTx {")
}

/// The ONE field reader both universes use: the `pub name:` lines of the struct whose head is `head`.
pub fn struct_public_fields(src: &str, head: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(start) = src.find(head) else {
        return out;
    };
    let body = &src[start..];
    let end = body.find("\n}").unwrap_or(body.len());
    for line in body[..end].lines().skip(1) {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("pub ") {
            if let Some(name) = rest.split(':').next() {
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// ⭐ DB-350 — which censused ask each wallet-facing `want_*` door raises. A door is a node function an RPC handler
/// calls to turn a wallet's selector into an ask a PEER receives; the peer views that ask, so it is a surface.
pub const WANT_DOOR_ASKS: &[(&str, &str)] = &[
    ("want_record_at_id", "Ask::record_by_id"),
    ("want_record_at_ordinal", "Ask::record_by_ordinal"),
    ("want_account_bucket", "Ask::account_bucket"),
];

/// Doors deleted at source because the ask they raised named an item a wallet owns. A handler that calls one again
/// reopens a closed leak.
pub const RETIRED_WANT_DOORS: &[&str] = &["want_record_by_cm"];

/// The `want_*` doors a source text calls — every `.want_<ident>(`.
pub fn want_doors(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, _) in src.match_indices(".want_") {
        let rest = &src[i + 1..];
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').collect();
        if rest[name.len()..].starts_with('(') {
            out.insert(name);
        }
    }
    out
}

/// The handler half of rpc_http.rs — everything before its first test module: the text a wallet's request runs.
pub fn rpc_handler_half(src: &str) -> &str {
    src.split("\n#[cfg(test)]\n").next().unwrap_or(src)
}

/// The ask universe's gaps: a door that names no censused ask, a door mapped to a surface the register lacks, a retired
/// door called again, or a reader that found too few doors to be trusted.
#[must_use]
pub fn want_door_gaps(rpc_src: &str) -> Vec<String> {
    let doors = want_doors(rpc_handler_half(rpc_src));
    let mut gaps = Vec::new();
    if doors.len() < 3 {
        gaps.push(format!(
            "the door reader found only {doors:?} in rpc_http.rs's handlers — a derivation that finds nothing is \
             green and worthless"
        ));
    }
    for d in &doors {
        if RETIRED_WANT_DOORS.contains(&d.as_str()) {
            gaps.push(format!("`{d}` is RETIRED (its ask named an item a wallet owns) and a handler calls it again"));
            continue;
        }
        match WANT_DOOR_ASKS.iter().find(|(door, _)| door == d) {
            None => gaps.push(format!(
                "`{d}` turns a wallet's selector into an ask a peer receives and names NO censused surface — map it in \
                 WANT_DOOR_ASKS and answer content / shape / linkage / ordering"
            )),
            Some((_, s)) if !SURFACES.iter().any(|x| x.name == *s) => {
                gaps.push(format!("`{d}` maps to `{s}`, which the register lacks"));
            }
            _ => {}
        }
    }
    gaps
}

/// ⭐⭐⭐ DB-196b — THE PRIVACY CENSUS'S UNIVERSE CHECK, AS A FUNCTION THE READINESS REPORT CAN ASK.
///
/// Same hole as the value-creation census (DB-196): `harness::readiness::live_criteria` counts open
/// `SURFACES` and reads ✅ whether or not `every_public_block_field_is_in_the_census` still passes. A
/// block field added tomorrow is invisible to a viewer-leak criterion that only counts the surfaces
/// somebody already wrote down.
///
/// Returning the gaps lets the test assert they are empty AND the readiness report count them as open
/// surfaces, so a census that stops covering the block turns the criterion red by construction.
#[must_use]
pub fn census_universe_gaps() -> Vec<String> {
    let mut gaps = Vec::new();
    let Ok(src) = std::fs::read_to_string("src/block.rs") else {
        // ⛔ NOT SILENCE: a universe that cannot be read must not read as a covered one.
        gaps.push(
            "the block source could not be read, so the public-field universe is UNCHECKED".to_string(),
        );
        return gaps;
    };
    let fields = block_public_fields(&src);
    if fields.len() < 5 {
        gaps.push(format!(
            "the public-field reader found only {} field(s) on `Block` — a derivation that finds \
             nothing is green and worthless, so the census's universe is not established",
            fields.len()
        ));
    }
    let named: BTreeSet<String> = SURFACES
        .iter()
        .filter_map(|s| s.name.strip_prefix("Block::").map(str::to_string))
        .collect();
    for f in fields.difference(&named) {
        gaps.push(format!(
            "`Block::{f}` travels on the wire and is in NO privacy census — a viewer sees it, so it \
             must answer content / shape / linkage / ordering"
        ));
    }
    // ⛔ THE OTHER DIRECTION — A ROW FOR A FIELD THAT NO LONGER EXISTS. MEASURED 2026-10-03: `Block::del_set` was retired
    // with the deletion model by the Z-build (2026-09-22) and its row stayed here, CLOSED, for eleven days — a stale row
    // reads as coverage while protecting nothing (the same defect `vacuity.rs` refuses for a deleted gate). `PqTx` had
    // this check in its own pin; `Block` had none, and neither fed the sweep.
    for f in named.difference(&fields) {
        gaps.push(format!(
            "census row `Block::{f}` names a field `Block` no longer has — a stale row reads as coverage; delete it or \
             census what replaced it"
        ));
    }
    // ⭐ DB-329 — THE SECOND OBJECT EVERY NODE RECEIVES: the gossiped transaction. Same rule, same reader.
    let Ok(tx_src) = std::fs::read_to_string("src/mempool.rs") else {
        gaps.push(
            "the transaction source could not be read, so the gossiped-field universe is UNCHECKED".to_string(),
        );
        return gaps;
    };
    let tx_fields = pqtx_public_fields(&tx_src);
    if tx_fields.len() < 5 {
        gaps.push(format!(
            "the public-field reader found only {} field(s) on `PqTx` — a derivation that finds nothing is green \
             and worthless, so the gossiped universe is not established",
            tx_fields.len()
        ));
    }
    let tx_named: BTreeSet<String> = SURFACES
        .iter()
        .filter_map(|s| s.name.strip_prefix("PqTx::").map(str::to_string))
        .collect();
    for f in tx_fields.difference(&tx_named) {
        gaps.push(format!(
            "`PqTx::{f}` is gossiped to every node and is in NO privacy census — a viewer sees it, so it must \
             answer content / shape / linkage / ordering"
        ));
    }
    for f in tx_named.difference(&tx_fields) {
        gaps.push(format!(
            "census row `PqTx::{f}` names a field `PqTx` no longer has — a stale row reads as coverage; delete it or \
             census what replaced it"
        ));
    }
    // ⭐ DB-350 — THE THIRD UNIVERSE: the asks a node sends a peer on its wallet's behalf. Every `want_*` door a
    // wallet-facing RPC handler calls raises one, and each must name a censused `Ask::` surface.
    let Ok(rpc_src) = std::fs::read_to_string("src/rpc_http.rs") else {
        gaps.push("the RPC source could not be read, so the wallet-facing ask universe is UNCHECKED".to_string());
        return gaps;
    };
    gaps.extend(want_door_gaps(&rpc_src));
    gaps
}


#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// `Block::account_targets` measured from the refusal side: an honest produced block passes the gossip
    /// door (`validate_full_body_commitments`) and the reduced-carrier door every other placement asks
    /// (`validate_carried_body_commitments`), and the same block carrying 64 B of targets — re-bound to
    /// its own `account_targets_root`, so the root check cannot be what refuses it — fails both with
    /// `AccountTargetsCarried`; the pool refuses a transaction carrying any. The calibration arm keeps a
    /// refusal for any other reason from reading as this one.
    fn account_targets_refused_at_every_door() -> bool {
        use crate::consensus::{validate_carried_body_commitments as carried, validate_full_body_commitments as full};
        use crate::consensus::ConsensusError::AccountTargetsCarried;
        let mut n = crate::node::Node::with_params(crate::block::genesis_block(), crate::params::ChainParams::default())
            .expect("a node");
        let b = n
            .produce(5_000, crate::hash::Hash32::hash(b"rf3-at"), crate::hash::Hash32::hash(b"rf3-mc"))
            .expect("produces");
        assert!(full(&b).is_ok() && carried(&b).is_ok(), "CALIBRATION: the honest block passes both doors");
        let mut forged = b.clone();
        forged.account_targets = vec![0xEEu8; 64];
        forged.header.account_targets_root = crate::block::da_sidecar_root_of(&forged.account_targets);
        let mut tx = crate::node::tests::grind_tx(b"rf3-at-tx", 17, vec![crate::hash::Hash32::hash(b"rf3-nf")], 0);
        tx.account_targets = vec![0x22u8; 64];
        matches!(full(&forged), Err(AccountTargetsCarried))
            && matches!(carried(&forged), Err(AccountTargetsCarried))
            && crate::mempool::Mempool::new().accept(tx).err() == Some(crate::mempool::MempoolError::AccountTargetsCarried)
    }


    fn block_src() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/block.rs"))
            .expect("the block module is readable")
    }

    /// ⛔ MEASUREMENT, NOT DECLARATION — what does an observer read off a block's SHAPE?
    ///
    /// Two blocks, different real activity, same everything else. Every field whose byte length differs
    /// is a field whose length is a readout of how busy the block was. This prints the census the
    /// register must then match — the numbers decide, not the comment.
    #[test]
    fn an_observer_cannot_read_real_activity_off_a_blocks_shape() {
        let sizes = crate::node::tests::block_field_sizes_for_activity();
        let (q1, q2, busy) = (&sizes[0], &sizes[1], &sizes[2]);
        let mut moved: Vec<String> = Vec::new();
        let mut noisy: Vec<String> = Vec::new();
        let mut unexercised: Vec<String> = Vec::new();
        eprintln!("[privacy] block field sizes — quiet · quiet(control) · busy:");
        for (name, a) in q1 {
            let (b, c) = (q2.get(name).copied().unwrap_or(0), busy.get(name).copied().unwrap_or(0));
            // A field that already differs between two IDENTICAL quiet blocks is wobbling on its own.
            // That is noise (a PoW nonce is a different length on every solve), never a readout.
            let flag = if *a != b {
                noisy.push(name.clone());
                "noise (moves between two quiet blocks)"
            } else if *a != c {
                moved.push(name.clone());
                "⛔ READS REAL ACTIVITY"
            } else if *a == 0 && c == 0 && name == "output_notes" {
                // §RF-3 (2026-10-24): `#[serde(skip)]` since DB-165, and the busy fixture ASSERTS its block holds local
                // output notes (`block_field_sizes_for_activity`'s calibration) — so this 0 is the skip measured with
                // bytes present to leak, not an empty field read as constant.
                "constant (measured: 0 B on the wire, local notes held)"
            } else if *a == 0 && c == 0 && name == "cover_key" {
                // §20.2 (2026-10-28, lane funds): `#[serde(skip)]` like `output_notes`, and the probe measures the wire
                // with and without the field while every probe block HOLDS a key (the producer draws one per block:
                // `cover_key.is_some()` is the calibration of `a_quiet_blocks_cover_secret_is_not_regenerable_from_the_
                // served_stream`) — so this 0 is the skip measured with 32 secret bytes present to leak, not an empty
                // field read as constant.
                "constant (measured: 0 B on the wire, a 32-B key held per block)"
            } else if *a == 0 && c == 0 && name == "wide_objects" {
                // §22b (2026-10-28, lane funds): the probe holds a 1-KiB object on every block it weighs, so this 0 is
                // the skip measured with bytes present to leak, not an empty field read as constant.
                "constant (measured: 0 B on the wire, a 1-KiB wide object held)"
            } else if *a == 0 && c == 0 && name == "account_targets" {
                // §RF-3 (2026-10-24): no honest fixture can carry one, so the 0 is proven from the other side —
                // a block that DOES carry targets (bound to its own root) is refused at both body doors.
                assert!(account_targets_refused_at_every_door(), "⛔ a block carrying account targets was admitted");
                "constant (measured: a carrying block is refused at every door)"
            } else if *a == 0 && c == 0 && name == "cover_transition" {
                // §18 (2026-10-28): RETIRED — the producer lays no cover transition (a stated spend's 32 tags are its own 16
                // ledger rows, chained by the tag ledger). The 0 is proven from the other side, not read as a quiet
                // constant: the busy calibration in `node::tests` asserts the busy block carries NO cover transition AND a
                // non-empty tag ledger, and `rf3_a_produced_busy_ledger_block_…` weighs busy = quiet with the field 0 on
                // both. Its deletion from `Block` is the re-genesis bundle's.
                "constant (measured: RETIRED — none laid; the busy calibration asserts its absence beside the tag ledger)"
            } else if *a == 0 && c == 0 {
                // ⛔⛔⛔ A VACUOUS PASS LOOKS EXACTLY LIKE A REAL ONE, AND THAT IS THE WHOLE TRAP.
                //
                // A sidecar that is EMPTY on the busy fixture too was never exercised: its length cannot
                // contradict a `Shape::Constant` claim because it has no length to compare. Six of twelve
                // surfaces sat at `0 · 0 · 0` and the census called every one of them constant. That is the
                // same blind spot the weld hit at n=1 — a single-row table cannot test degree, and an
                // unexercised field cannot test shape — and it was found the same way: by asking what the
                // instrument would have had to SEE to fail.
                //
                // Reported as UNPROVEN rather than as constant, and counted below, so an unexercised
                // surface is visible instead of silently green. The fix for one is a fixture that carries
                // it, not a louder claim.
                unexercised.push(name.clone());
                "⚠️ UNPROVEN (empty on every fixture — nothing to measure)"
            } else {
                "constant (measured)"
            };
            eprintln!("[privacy]   {name:<18} {a:>8} · {b:>8} · {c:>8}   {flag}");
        }
        eprintln!(
            "[privacy] {} of {} surfaces READ REAL ACTIVITY: {moved:?} · {} noisy: {noisy:?} · \
             {} UNPROVEN (never exercised): {unexercised:?}",
            moved.len(),
            q1.len(),
            noisy.len(),
            unexercised.len()
        );
        // §RF-3 (2026-10-24): every surface is now exercised (account_targets by its measured refusal), so an
        // unexercised one is a regression in the fixture, never a quiet constant.
        assert!(unexercised.is_empty(), "⛔ UNPROVEN surfaces (empty on every fixture): {unexercised:?}");
        // ⛔ THE CENSUS MUST MATCH THE MEASUREMENT. A surface the register calls `Shape::Constant` while
        // the scale says it moves is a claim the code contradicts — the exact failure mode a declared-only
        // census cannot have.
        for name in &moved {
            let full = format!("Block::{name}");
            let declared = SURFACES.iter().find(|s| s.name == full);
            assert!(
                declared.is_none_or(|s| matches!(s.shape, Shape::TracksActivity(_) | Shape::PublicActs(_)))
                    || FILED_OPEN.contains(&full.as_str()),
                "⛔⛔⛔ `{full}` IS DECLARED Shape::Constant AND THE SCALE SAYS OTHERWISE: stable across \
                 two quiet blocks, then {} bytes on a busy one instead of {}. An observer reads real \
                 activity off its LENGTH however well its CONTENT is sealed.",
                busy.get(name).copied().unwrap_or(0),
                q1.get(name).copied().unwrap_or(0)
            );
        }
    }

    /// ⛔ THE CENSUS CANNOT DRIFT FROM THE STRUCT. A new public `Block` field fails here until someone
    /// writes down what viewing it reveals.
    #[test]
    fn every_public_block_field_is_in_the_census() {
        let fields = block_public_fields(&block_src());
        assert!(
            fields.len() >= 10,
            "the field reader found only {} fields — it has drifted from `pub struct Block`",
            fields.len()
        );
        let named: BTreeSet<String> = SURFACES
            .iter()
            .filter_map(|s| s.name.strip_prefix("Block::").map(str::to_string))
            .collect();
        let missing: Vec<&String> = fields.difference(&named).collect();
        assert!(
            missing.is_empty(),
            "⛔⛔⛔ {} PUBLIC BLOCK FIELD(S) HAVE NO PRIVACY ANSWER: {:?}\n\
             Every field of a block is something an observer receives. Say what viewing it reveals — \
             CONTENT, SHAPE, LINKAGE, ORDERING — or file it in FILED_OPEN with its kill-list section. \
             ⛔ SHAPE is measured, not declared: `an_observer_cannot_read_real_activity_off_a_blocks_shape` \
             will contradict a wrong claim.",
            missing.len(),
            missing
        );
    }

    /// ⭐⭐⭐ DB-329 — THE CENSUS CANNOT DRIFT FROM THE GOSSIPED TRANSACTION EITHER. `PqTx` is postcard-encoded whole
    /// for gossip, so every public field reaches every node exactly as a block field does; a field with no answer
    /// fails here. MEASURED (the reason this exists): DB-327's stake leak (`stake_notes` = cm ‖ amount ‖ future
    /// nullifier) rode this struct while the census read only `Block`, and criterion 3 could not count it.
    /// ⛔ WHAT IS NOT CLAIMED: the `PqTx` SHAPE answers are READ from the builders, not yet measured by a probe the
    /// way `every_public_block_field_is_actually_measured_by_the_shape_probe` measures the block's; a transaction
    /// shape probe is the follow-on, and until it exists these answers are declarations with their sources named.
    /// CALIBRATION: the reader finds the fields a transaction is known to carry, so an empty read cannot pass.
    #[test]
    fn every_gossiped_pqtx_field_is_in_the_census() {
        // TWO-PARTY-REVIEWED: a source census over a struct's declared fields — no capability runs and nothing crosses
        // a boundary here; the two parties this surface faces (the sender and every gossip receiver) are what the
        // census's answers describe, and the register's cross-node pins exercise the transaction itself.
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mempool.rs"))
            .expect("the mempool module is readable");
        let fields = pqtx_public_fields(&src);
        for known in ["nullifiers", "output_notes", "account_targets", "stake_notes", "membership_tip"] {
            assert!(fields.contains(known), "calibration: the PqTx reader must see `{known}` (found {fields:?})");
        }
        let named: BTreeSet<String> = SURFACES
            .iter()
            .filter_map(|s| s.name.strip_prefix("PqTx::").map(str::to_string))
            .collect();
        let missing: Vec<&String> = fields.difference(&named).collect();
        assert!(
            missing.is_empty(),
            "⛔⛔⛔ {} GOSSIPED TRANSACTION FIELD(S) HAVE NO PRIVACY ANSWER: {:?}\n\
             Every field of a gossiped transaction reaches every node. Say what viewing it reveals — CONTENT, \
             SHAPE, LINKAGE, ORDERING — or file it in FILED_OPEN.",
            missing.len(),
            missing
        );
        let stale: Vec<&String> = named.difference(&fields).collect();
        assert!(stale.is_empty(), "⛔ census rows for PqTx fields that no longer exist: {stale:?}");
        let universe = census_universe_gaps();
        assert!(
            !universe.iter().any(|g| g.contains("PqTx")),
            "the readiness universe check agrees with this test: {universe:?}"
        );
    }

    /// ⛔⛔⛔ EVERY PUBLIC BLOCK FIELD MUST BE **PROBED**, NOT MERELY DECLARED.
    ///
    /// `every_public_block_field_is_in_the_census` checks every field has a written ANSWER. Nothing
    /// checked that the SHAPE MEASUREMENT can see it — and shape is the one axis this census insists is
    /// measured rather than declared. MEASURED 2026-09-24: `Block` has 13 public fields and the size
    /// probe enumerated 12. The missing one, `cover_transition`, sat in `SURFACES` declaring
    /// `Shape::TracksActivity("presence separates a spending block from a quiet one")` — an assertion no
    /// measurement could confirm or refute.
    ///
    /// ⭐ AND THE DIRECTION OF THAT ERROR IS NOT SAFE EITHER WAY. On the same run `pow_proof` was
    /// declared `TracksActivity("1 byte shorter on a block carrying payments")` and MEASURED CONSTANT at
    /// 32·32·32 — a FALSE blocker that had been carried as real. An unmeasured declaration is noise
    /// whichever way it points, and a census that runs on noise is not a census.
    #[test]
    fn every_public_block_field_is_actually_measured_by_the_shape_probe() {
        let fields = block_public_fields(&block_src());
        let sizes = crate::node::tests::block_field_sizes_for_activity();
        let probed: BTreeSet<String> = sizes[0].keys().cloned().collect();
        let unprobed: Vec<&String> = fields.difference(&probed).collect();
        assert!(
            unprobed.is_empty(),
            "⛔⛔⛔ {} PUBLIC BLOCK FIELD(S) ARE DECLARED BUT NEVER MEASURED: {:?}\n\
             SHAPE is measured, not declared — a field the probe cannot see carries whatever claim its \
             SURFACES entry happens to make, forever, with nothing able to contradict it. Add it to \
             `block_field_sizes_for_activity`.",
            unprobed.len(),
            unprobed
        );
    }

    /// ⭐ §POLES T1 (2026-10-26) — CONTENT, MEASURED ON THE WHOLE WIRE. The Block rows claimed "no note payload
    /// travels, only its commitment" by declaration. This reads it: every real note the busy block holds locally
    /// (`output_notes`, serde-skipped) must be named on the wire by its 32-B commitment ONLY — no 32-B window of
    /// any note's body may appear anywhere in the block's postcard encoding (header, tx_ids, every sidecar, the
    /// nullifier proof), so an observer of the block reads no payload and no count off a payload.
    #[test]
    fn a_blocks_wire_carries_no_note_payload_only_its_commitments() {
        const NOTE: usize = 1153;
        let ([_, _, busy], _) = crate::node::tests::blocks_for_activity();
        let notes = &busy.output_notes;
        assert!(
            !notes.is_empty() && notes.len() % NOTE == 0,
            "CALIBRATION: the busy block holds whole local notes ({} B) — else there is no payload to look for",
            notes.len()
        );
        let carrier: BTreeSet<&[u8]> = busy.note_commitments.chunks_exact(32).collect();
        let wire = postcard::to_allocvec(&busy).expect("a block encodes");
        let windows: std::collections::HashSet<&[u8]> = wire.windows(32).collect();
        let (mut named, mut leaked) = (0usize, Vec::new());
        for (k, note) in notes.chunks_exact(NOTE).enumerate() {
            // a carrier slot is `blake3(note)` (`assemble_note_commitment_carrier`)
            let cm = *crate::hash::Hash32::hash(note).as_bytes();
            if carrier.contains(&cm[..]) {
                named += 1;
            }
            if let Some(off) = note[32..].windows(32).position(|w| w != [0u8; 32] && windows.contains(w)).map(|o| o + 32) {
                // name the field that carries it, and whether the WHOLE note travels (then blake3 of it names its slot)
                let fields: Vec<(&str, Vec<u8>)> = vec![
                    ("header", postcard::to_allocvec(&busy.header).unwrap_or_default()),
                    ("note_transition", postcard::to_allocvec(&busy.note_transition).unwrap_or_default()),
                    ("cover_transition", postcard::to_allocvec(&busy.cover_transition).unwrap_or_default()),
                    ("member_transition", postcard::to_allocvec(&busy.member_transition).unwrap_or_default()),
                    ("nullifier_proof", postcard::to_allocvec(&busy.nullifier_proof).unwrap_or_default()),
                    ("pow_proof", busy.pow_proof.clone()),
                    ("note_commitments", busy.note_commitments.clone()),
                    ("oli_tags", busy.oli_tags.clone()),
                    ("account_targets", busy.account_targets.clone()),
                    ("bond_set", busy.bond_set.clone()),
                    ("credit_set", busy.credit_set.clone()),
                    ("dir_set", busy.dir_set.clone()),
                    ("letter_set", busy.letter_set.clone()),
                ];
                let w = &note[off..off + 32];
                let at: Vec<&str> = fields.iter().filter(|(_, b)| b.windows(32).any(|x| x == w)).map(|(n, _)| *n).collect();
                let whole = wire.windows(NOTE).any(|x| x == note);
                eprintln!("[t1-content]   note {k}: body window at {off} found in {at:?} · whole note on the wire {whole}");
                leaked.push((k, off));
            }
        }
        eprintln!(
            "[t1-content] busy: {} local notes · {named} named by commitment in the carrier · wire {} B · body leaks {:?}",
            notes.len() / NOTE,
            wire.len(),
            leaked
        );
        assert_eq!(
            named,
            notes.len() / NOTE,
            "CALIBRATION: every real note is named on the wire by its commitment — else the carrier is not what it claims"
        );
        // THE DB-165 ATTACK ON THE WHOLE WIRE: a slot is `blake3(note)`, so any whole note an observer can cut out of
        // the wire names its carrier slot as REAL — and the count of such hits counts the reals.
        let unmasked = wire
            .windows(NOTE)
            .filter(|w| carrier.contains(&crate::hash::Hash32::hash(w).as_bytes()[..]))
            .count();
        eprintln!("[t1-content] carrier slots an observer names as real by hashing a wire window: {unmasked}");
        // THE SAME ATTACK WITHOUT HASHING: a carrier slot copied verbatim anywhere else on the wire (a credit_set note
        // ref `cm ‖ H(note)`, any sidecar) names that slot as REAL. Encode the block with its carrier cleared, so the
        // only place a slot may appear is the carrier itself, and look for every slot in every 32-B window.
        let mut bare = busy.clone();
        bare.note_commitments.clear();
        let bare_wire = postcard::to_allocvec(&bare).expect("a block encodes");
        let bare_windows: std::collections::HashSet<&[u8]> = bare_wire.windows(32).collect();
        let named_verbatim: Vec<usize> =
            carrier.iter().enumerate().filter(|(_, s)| bare_windows.contains(*s)).map(|(i, _)| i).collect();
        let fields: Vec<(&str, &[u8])> = vec![
            ("credit_set", busy.credit_set.as_slice()),
            ("bond_set", busy.bond_set.as_slice()),
            ("dir_set", busy.dir_set.as_slice()),
            ("letter_set", busy.letter_set.as_slice()),
            ("account_targets", busy.account_targets.as_slice()),
            ("oli_tags", busy.oli_tags.as_slice()),
            ("output_notes", busy.output_notes.as_slice()),
        ];
        for s in carrier.iter().filter(|s| bare_windows.contains(*s)) {
            let at: Vec<&str> = fields.iter().filter(|(_, b)| b.windows(32).any(|x| x == *s)).map(|(n, _)| *n).collect();
            eprintln!("[t1-content]   carrier slot named verbatim off the carrier in {at:?}");
        }
        eprintln!(
            "[t1-content] carrier slots ({}) named verbatim elsewhere on the wire: {}",
            carrier.len(),
            named_verbatim.len()
        );
        assert!(
            leaked.is_empty(),
            "⛔⛔⛔ NOTE PAYLOAD ON THE WIRE: (note, offset) {leaked:?} — a block may name a note only by its commitment"
        );
        assert_eq!(unmasked, 0, "⛔⛔⛔ {unmasked} CARRIER SLOT(S) UNMASKED: a whole note on the wire hashes to its slot");
        assert!(
            named_verbatim.is_empty(),
            "⛔⛔⛔ {} CARRIER SLOT(S) NAMED VERBATIM off the carrier — a slot may appear only in note_commitments",
            named_verbatim.len()
        );
    }

    /// ⭐ §POLES T1 (2026-10-26) — THE COVER SECRET IS NOT ON THE WIRE. `cover::block_cover_secret` and
    /// `cover::header_seed` take the block's real note BODIES as their only secret input; a note that travels whole
    /// (the reward, by design) is known to every observer. So in every probe block — quiet and busy — at least one
    /// real body must be absent from the wire, else an observer regenerates the block's cover and counts its reals.
    #[test]
    fn every_blocks_cover_secret_keeps_a_real_body_off_the_wire() {
        const NOTE: usize = 1153;
        let ([q1, q2, busy], _) = crate::node::tests::blocks_for_activity();
        for (name, b) in [("quiet1", &q1), ("quiet2", &q2), ("busy", &busy)] {
            let wire = postcard::to_allocvec(b).expect("a block encodes");
            let total = b.output_notes.len() / NOTE;
            let whole = b.output_notes.chunks_exact(NOTE).filter(|n| wire.windows(NOTE).any(|w| w == *n)).count();
            eprintln!("[t1-secret] {name}: {total} real bodies · {whole} whole on the wire");
            assert!(total > 0, "CALIBRATION: {name} holds its real bodies locally");
            assert!(
                whole < total,
                "⛔⛔⛔ {name}: all {total} real bodies travel whole — `block_cover_secret`/`header_seed` are public"
            );
        }
    }

    /// ⭐ §POLES T1 (2026-10-26) — THE COVER SECRET IS NOT IN THE SERVED STREAM EITHER. The wire is not the
    /// observer's whole universe: every node serves every recorded note whole on `/get_pq_notes`
    /// (`Node::notes_page_budgeted`), cm in front, and the record a note is served in names its block. A real body
    /// of a block is therefore PUBLIC if it travels whole on the block's wire, OR it is served and identifiable as
    /// that block's — by the block's seed rule (`cover::is_seed_note_in`, §18.1) or by its cm standing on the block's wire (a
    /// credit's commitment). If every real body of a quiet block is public, its cover secret is regenerable from
    /// public data and the DB-165 attack runs through the stream. PREMISE MEASURED: the quiet producer's served page
    /// holds the block's real bodies (else "served" is assumed, not measured).
    #[test]
    fn a_quiet_blocks_cover_secret_is_not_regenerable_from_the_served_stream() {
        const NOTE: usize = 1153;
        let (q, producer) = crate::node::tests::quiet_block_and_its_producer();
        let wire = postcard::to_allocvec(&q).expect("a block encodes");
        // THE PUBLIC STREAM (`/get_pq_notes` = `pq_notes_from`, one `(ordinal, unit)` per served unit), regrouped per
        // record as `(address, units ‖, _)` — the peer page (`notes_page_budgeted`) is the stripped B13 lane, not the
        // stream a key-less observer reads (2026-10-28, lane funds).
        let page: Vec<(u64, Vec<u8>, Vec<u8>)> = {
            let (units, _top) = producer.pq_notes_from(0, 1 << 16);
            let mut by_ord: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
            for (ord, unit) in units {
                by_ord.entry(ord).or_default().extend_from_slice(&unit);
            }
            by_ord
                .into_iter()
                .filter_map(|(ord, notes)| producer.da_addr_at_ordinal(ord).map(|seq| (seq, notes, Vec::new())))
                .collect()
        };
        let served: BTreeSet<Vec<u8>> =
            page.iter().flat_map(|(_, notes, _)| notes.chunks_exact(NOTE).map(|n| n.to_vec())).collect();
        let reals: Vec<&[u8]> = q.output_notes.chunks_exact(NOTE).collect();
        // §20.2 (2026-10-28): the cover secret is `record_cover_secret(seq, KEY)` / `header_seed(reals, KEY)` — the
        // producer-drawn cover key rides the LedgerRecord lane beside the reals and NEVER the block's wire or the served
        // stream. The observer of this pin is a stream reader with no key: it cannot evaluate the seed equation
        // (`is_seed_note_in` takes the key), so "identifiable" is a commitment standing on the block's wire alone.
        // MEASURED before the re-statement (privacy-113.log): the pin handed the observer the producer's key and read
        // "all 2 real bodies of a quiet block are public" — a conclusion the key-less observer cannot reach.
        let key = q.cover_key.expect("CALIBRATION: the producer's block carries its cover key beside the body");
        let served_bytes: Vec<u8> = page.iter().flat_map(|(_, notes, _)| notes.iter().copied()).collect();
        assert!(
            !wire.windows(32).any(|w| w == &key[..]) && !served_bytes.windows(32).any(|w| w == &key[..]),
            "⛔⛔⛔ the block's cover key is on the wire or in the served stream — the cover secret is regenerable"
        );
        let public_seed = crate::cover::header_seed(&q.output_notes, &crate::cover::idle_cover_key(0));
        assert_ne!(
            public_seed,
            crate::cover::header_seed(&q.output_notes, &key),
            "⛔⛔⛔ the header seed does not depend on the key — every real body public would regenerate it"
        );
        let (mut whole, mut served_n, mut by_cm, mut public) = (0, 0, 0, 0);
        for n in &reals {
            let on_wire = wire.windows(NOTE).any(|w| w == *n);
            let is_served = served.contains(*n);
            let cm_on_wire = wire.windows(32).any(|w| w == &n[..32]);
            whole += on_wire as usize;
            served_n += is_served as usize;
            by_cm += (is_served && cm_on_wire) as usize;
            public += (on_wire || (is_served && cm_on_wire)) as usize;
        }
        eprintln!(
            "[t1-stream] quiet: {} real bodies · {whole} whole on the wire · {served_n} served · {by_cm} served+cm on \
             wire · {public} public (key-less observer) · served page {} records",
            reals.len(),
            page.len()
        );
        assert!(!reals.is_empty(), "CALIBRATION: the quiet block holds its real bodies locally");
        assert!(
            served_n + whole >= reals.len(),
            "CALIBRATION: every real body is on the wire or in the served stream — else the premise is unmeasured"
        );
        // MEASURED (privacy-117.log): "2 real bodies · 1 whole on the wire · 2 served+cm on wire · 2 public" — the reward
        // rides whole in `credit_set` (the FILED_OPEN credit_set row, pinned by `a_blocks_wire_carries_no_note_payload…`)
        // and the seed note's front IS a published cover cell (§18.1), so BOTH of a quiet block's reals are identifiable.
        // Under §20.2 that names the design's two constant public rows (one seed, one reward per block — no count in
        // them) and NOT the cover: the cover units are `cover_note_det(record_cover_secret(seq, KEY), slot)`, and a
        // key-less observer's strongest regeneration is the one public key. THE LAW: no served unit of the quiet block's
        // record is a key-less regeneration of its cover — the 254 cover units are indistinguishable from reals to a
        // reader with no key, so identifying the public rows counts nothing.
        let quiet_record = page
            .iter()
            .find(|(_, notes, _)| reals.iter().all(|r| notes.chunks_exact(NOTE).any(|u| u == *r)))
            .expect("CALIBRATION: the served page holds the quiet block's record (every real body in one record)");
        let keyless = crate::cover::assemble_fixed_note_payload(
            &q.output_notes,
            quiet_record.0,
            &crate::cover::idle_cover_key(quiet_record.0),
        );
        let keyless_cover = keyless
            .chunks_exact(NOTE)
            .filter(|u| !reals.contains(u))
            .filter(|u| quiet_record.1.chunks_exact(NOTE).any(|s| s == *u))
            .count();
        eprintln!(
            "[t1-stream] quiet: {public} of {} reals identified (the seed front + the reward, the design's constant public \
             rows) · {keyless_cover} served unit(s) regenerated by a key-less observer",
            reals.len()
        );
        assert_eq!(
            quiet_record.1.len(),
            crate::cover::BLOCK_FIXED_NOTE_COUNT * NOTE,
            "CALIBRATION: the quiet block's record is served in the constant 256-unit shape"
        );
        assert_eq!(
            keyless_cover, 0,
            "⛔⛔⛔ a key-less observer regenerated {keyless_cover} served cover unit(s) of the quiet block — the cover secret \
             is public data"
        );
    }

    /// ⭐ §POLES T1 (2026-10-26) — COUNT METADATA ON THE SERVED STREAM. `notes_page_budgeted` serves each record as
    /// `da_load(seq).concat()` — the REAL bodies only — so a record's served length is k × 1153 B and any `/get_pq_notes`
    /// reader counts every block's real notes without breaking anything. Digital cash pads a count to a constant: every
    /// served record is the block's full 256-unit shape, whatever k is. PREMISE MEASURED: the page is non-empty.
    #[test]
    fn a_served_record_does_not_reveal_its_real_note_count() {
        const NOTE: usize = 1153;
        let (_q, producer) = crate::node::tests::quiet_block_and_its_producer();
        // THE PUBLIC STREAM is `/get_pq_notes` = `pq_notes_from` (the explorer, the IDE SDK, any indexer): one entry per
        // served UNIT, `(ordinal, 1,153 B)`. MEASURED 2026-10-28 (lane funds): this pin read the PEER page
        // (`notes_page_budgeted`) instead — the stripped record lane the user decided for peers (B13) — and "closing"
        // it there (24d308a) slowed the eclipse victim's page-walk recovery past its budget (reverted b0cace5). The
        // public route already served the constant shape; the pin now measures the surface it names.
        let (units, _top) = producer.pq_notes_from(0, 1 << 16);
        let mut per_ordinal: std::collections::BTreeMap<u64, (usize, BTreeSet<usize>)> = std::collections::BTreeMap::new();
        for (ord, unit) in &units {
            let e = per_ordinal.entry(*ord).or_default();
            e.0 += 1;
            e.1.insert(unit.len());
        }
        let counts: BTreeSet<usize> = per_ordinal.values().map(|(n, _)| *n).collect();
        let lens: BTreeSet<usize> = per_ordinal.values().flat_map(|(_, l)| l.iter().copied()).collect();
        eprintln!(
            "[t1-count] public route served {} record(s) · units per record {counts:?} · unit lengths {lens:?}",
            per_ordinal.len()
        );
        assert!(!per_ordinal.is_empty(), "CALIBRATION: the producer serves its records — else the stream is unmeasured");
        assert!(
            lens.iter().all(|l| *l == NOTE) && counts.iter().all(|c| *c == crate::cover::BLOCK_FIXED_NOTE_COUNT),
            "⛔⛔⛔ the public route served {counts:?} unit(s) per record of {lens:?} B ≠ the constant {} × {NOTE} B — a \
             reader counts a block's real notes off the served shape",
            crate::cover::BLOCK_FIXED_NOTE_COUNT
        );
    }

    /// ⭐ §POLES T1 (2026-10-26) — LINKAGE, MEASURED ACROSS TWO BLOCKS OF ONE PRODUCER. A cover item that a producer
    /// lays again in its next block is marked as cover by the repeat (a real commitment, tag or tx id is unique), and
    /// a constant pad (an all-zero 32-B chunk) counts the reals by subtraction. So: the 32-B items of the busy block
    /// and of the same producer's next block — tx ids, carrier chunks, padded nullifier tags, letter chunks — are
    /// disjoint, and the carrier holds the same number of all-zero chunks in a quiet block as in a busy one.
    #[test]
    fn no_cover_item_repeats_across_two_blocks() {
        let ([q1, q2, busy], next) = crate::node::tests::blocks_for_activity();
        let next = next.expect("CALIBRATION: the busy producer lays a second block — else there is no pair to link");
        let zero = [0u8; 32];
        let items = |b: &crate::block::Block| -> BTreeSet<Vec<u8>> {
            let mut s = BTreeSet::new();
            s.extend(b.tx_ids.iter().map(|h| h.as_bytes().to_vec()));
            s.extend(b.note_commitments.chunks_exact(32).map(|c| c.to_vec()));
            s.extend(b.nullifier_proof.padded_tags.iter().map(|t| t.to_vec()));
            s.extend(b.letter_set.chunks_exact(32).map(|c| c.to_vec()));
            s.remove(&zero.to_vec());
            s
        };
        let zeros = |b: &crate::block::Block| b.note_commitments.chunks_exact(32).filter(|c| *c == zero).count();
        let (ib, inext, iq1) = (items(&busy), items(&next), items(&q1));
        let repeats: Vec<_> = ib.intersection(&inext).collect();
        eprintln!(
            "[t1-linkage] items busy {} · next {} · repeats {} · quiet∩busy {} (fixture nodes share a seed: info) · \
             quiet twin identical {} · zero pads quiet {} busy {} next {}",
            ib.len(),
            inext.len(),
            repeats.len(),
            iq1.intersection(&ib).count(),
            postcard::to_allocvec(&q1).ok() == postcard::to_allocvec(&q2).ok(),
            zeros(&q1),
            zeros(&busy),
            zeros(&next)
        );
        assert!(
            !ib.is_empty() && !inext.is_empty(),
            "CALIBRATION: both blocks carry 32-B items — else disjointness is vacuous"
        );
        assert!(
            repeats.is_empty(),
            "⛔⛔⛔ {} ITEM(S) REPEAT ACROSS TWO BLOCKS OF ONE PRODUCER — the repeat marks them as cover: {:?}",
            repeats.len(),
            repeats.iter().take(4).map(|v| &v[..8]).collect::<Vec<_>>()
        );
        assert_eq!(
            zeros(&q1),
            zeros(&busy),
            "⛔⛔⛔ THE CARRIER'S ZERO PADS COUNT THE REAL NOTES: quiet {} vs busy {}",
            zeros(&q1),
            zeros(&busy)
        );
    }

    /// ⭐⭐⭐ DB-165 — THE ATTACK, RUN AGAINST THE WIRE, AND IT FAILS.
    ///
    /// Before DB-165 this attack SUCCEEDED and this test was RED. A node read the real note count off
    /// `output_notes` (5,765 B / 1,153 = five), fed those same bytes to
    /// `block_cover_secret(real_notes, seq)` — whose only secret input they are — and regenerated all 251
    /// DA-record cover slots, naming the real ones. The record's padding was sound in isolation and
    /// defeated by the block carrying the reals in the clear.
    #[test]
    fn a_node_cannot_use_the_block_to_unmask_which_record_slots_are_real() {
        let sizes = crate::node::tests::block_field_sizes_for_activity();
        let (q1, busy) = (&sizes[0], &sizes[2]);

        // ⭐ NON-VACUITY FIRST: "the attacker learns nothing" is trivially true of an empty block.
        let carrier_q = q1.get("note_commitments").copied().unwrap_or(0);
        let carrier_b = busy.get("note_commitments").copied().unwrap_or(0);
        assert_eq!(
            carrier_b,
            crate::cover::BLOCK_NOTE_COMMITMENTS_BYTES,
            "calibration: the busy block must ship a full carrier, or there is no block to attack"
        );
        assert_eq!(carrier_q, carrier_b, "and the quiet block ships exactly the same width");

        let wire_notes = busy.get("output_notes").copied().unwrap_or(0);
        let wire_credits = busy.get("credit_set").copied().unwrap_or(0);
        eprintln!(
            "[db165] on the WIRE, busy block: output_notes {wire_notes} B, credit_set {wire_credits} B, \
             carrier {carrier_b} B (quiet carrier {carrier_q} B)"
        );
        assert_eq!(
            wire_notes, 0,
            "⛔⛔⛔ THE BLOCK STILL STATES ITS REAL NOTE COUNT ON THE WIRE: {wire_notes} B / 1153 is the \
             count, read with one division. Measured 5,765 B before DB-165; it must be ZERO now"
        );
        // ⛔⛔⛔ DB-224 — `credit_set` TRAVELS AGAIN, SO `wire_credits == 0` IS NO LONGER THE CLAIM, AND THE
        // CLAIM THAT REPLACES IT IS THE ONE THAT WAS ALWAYS THE POINT (docs/DB-224 §7, §8.7).
        //
        // DB-165 zeroed this field to stop a node regenerating the record's cover from the reals the block
        // carried — and in doing so stopped every peer applying the framed objects the block carries
        // (DB-224: the producer held a price mark, its peer held none). The set now travels in CARRIAGE
        // form: every note payload replaced by its 64-byte reference, enforced at consensus
        // (`CreditSetNotCarriage`). So the precise assertion is on the CONTENT: not one real note payload
        // byte in the carried set — asserted, with the regeneration attack itself run and failing, by
        // `db224_the_carried_credit_set_holds_no_payload_and_the_regeneration_attack_fails` below. Its
        // LENGTH still states the block's framed-object count; that SHAPE is filed open on its own line.
        assert!(
            wire_credits > 0,
            "CALIBRATION (DB-224): the busy block carries five credit justifiers, so its carried set must be \
             ON the wire — {wire_credits} B means the objects no longer travel and every peer stops applying \
             them again"
        );

        // The KDF is still deterministic, as any KDF is. That was never the defect: the defect was that
        // its secret INPUT rode the wire. Pinned as the distinction it is.
        let seq = 4_242_u64;
        assert_eq!(
            crate::cover::block_cover_secret(&[9u8; 1153], seq),
            crate::cover::block_cover_secret(&[9u8; 1153], seq),
            "calibration: deterministic derivation is not the defect — a travelling secret input was"
        );

        // ⭐⭐⭐ AND THE WHOLE CLAIM, AS ONE COMPARISON: a quiet block and a busy one must be
        // indistinguishable in EVERY field that travels.
        let mut differing: Vec<String> = Vec::new();
        for (name, q) in q1 {
            // ⛔ DB-224: EXACTLY ONE FIELD IS EXEMPT, BY NAME, AND IT IS FILED OPEN FOR THIS VERY AXIS —
            // `credit_set`'s length is the count of framed consensus objects the block applies (public by
            // design, and already delivered whole to every node by tx gossip). Its content is asserted
            // payload-free by the DB-224 test below; every other field must still match byte for byte.
            // §RF-3 (2026-10-24): the same exemption, by the same rule, for every field the register files open for
            // SHAPE — `note_transition` and `member_transition` measured 0 B quiet vs ~400 KB busy the moment the busy
            // block stated a spend (this comparison passed before only because it stated none). An exempt field is
            // printed and counted in FILED_OPEN, never silent; a field not filed open for SHAPE is not exempt.
            let full = format!("Block::{name}");
            if FILED_OPEN.contains(&full.as_str())
                && SURFACES.iter().any(|s| s.name == full && matches!(s.shape, Shape::TracksActivity(_)))
            {
                eprintln!(
                    "[privacy] FILED OPEN (shape): {full} quiet {q} B vs busy {} B",
                    busy.get(name).copied().unwrap_or(0)
                );
                continue;
            }
            let b = busy.get(name).copied().unwrap_or(0);
            if *q != b {
                differing.push(format!("{name}: quiet {q} B vs busy {b} B"));
            }
        }
        assert!(
            differing.is_empty(),
            "⛔⛔⛔ A QUIET BLOCK AND A BUSY ONE DIFFER ON THE WIRE, so an observer separates them by \
             SHAPE ALONE: {differing:?}. Every field a block ships must measure the same whether it \
             carried five payments or none."
        );
    }

    /// ⭐⭐⭐ DB-224 — THE CARRIED CREDIT SET HOLDS NO PAYLOAD, AND THE REGENERATION ATTACK, RUN ON THE WIRE,
    /// FAILS. The precise assertion §7 of docs/DB-224 named when the set was put back on the wire.
    ///
    /// A producer (node_a) stages five credited notes (high-entropy ciphertexts) with their justifying
    /// objects and produces. The ATTACKER is a real second party (node_b): it receives the block's wire
    /// bytes, grafts the block, and then tries to regenerate node_a's record from what those bytes expose.
    ///   1. CALIBRATION — the attack's machinery works: fed the REAL notes (what a pre-DB-165 wire, which
    ///      carried full objects, would have handed it), `assemble_fixed_note_payload_det` reproduces
    ///      node_a's own 256-unit record byte for byte — every cover slot named;
    ///   2. no 64-byte window of any real ciphertext occurs anywhere in the block's wire bytes, and node_b —
    ///      which grafted exactly those bytes — holds none of the five notes' records;
    ///   3. the attacker's best input — every note field the carried set exposes — yields a DIFFERENT
    ///      cover secret, and the record it regenerates from it is not node_a's record.
    /// The value path across parties is `db224_a_wrapped_mint_crosses_the_wire_without_its_payload_and_…`;
    /// this pin is the privacy half of the same wire.
    #[test]
    fn db224_the_carried_credit_set_holds_no_payload_and_the_regeneration_attack_fails() {
        use crate::cover::{assemble_fixed_note_payload, idle_cover_key, record_cover_secret, PQ_NOTE_BYTES};
        use crate::hash::Hash32;
        let testnet_node = || {
            let mut p = crate::params::ChainParams::default();
            p.genesis_parity_commit = crate::params::network_genesis_prefix("testnet");
            p.net_prefix_len = p.genesis_parity_commit.len();
            let mut g = crate::node::tests::genesis_block();
            g.header =
                crate::block::genesis_header_for_network(&crate::params::network_genesis_prefix("testnet"));
            let mut n = crate::node::Node::with_params(g, p).expect("a testnet node builds");
            // The premise is a block whose reals are EXACTLY the five credits. Since SATOSHI increment 1 a node with a
            // provisioned reward recipient lays a sixth (its reward) in every block; these parties run without one — a
            // real configuration — so the subject (the five credits' payloads never ride the wire) is measured alone.
            n.set_reward_recipient(None);
            n
        };
        let mut node_a = testnet_node();
        let mut node_b = testnet_node();
        let mut reals: Vec<Vec<u8>> = Vec::new();
        for i in 0..5u8 {
            let mut note = Hash32::hash(&[b'c', b'm', i]).as_bytes().to_vec();
            let mut ctr = 0u64;
            while note.len() < PQ_NOTE_BYTES {
                note.extend_from_slice(Hash32::hash(&[&[i][..], &ctr.to_le_bytes()[..]].concat()).as_bytes());
                ctr += 1;
            }
            note.truncate(PQ_NOTE_BYTES);
            let mut deposit_id = [0u8; 32];
            deposit_id.copy_from_slice(&note[..32]);
            node_a.stage_credit_note(note.clone());
            node_a.stage_credit_justifier(
                crate::bridge_credit_tx::BridgeCreditTx {
                    deposit_id,
                    asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                    amount: 1_000,
                    note: note.clone(),
                    owner_clue: Vec::new(),
                    attestors: Vec::new(),
                }
                .wire(),
            );
            reals.push(note);
        }
        let blk = node_a
            .produce(4_000, Hash32::hash(b"db224-census-fr"), Hash32::hash(b"db224-census-mc"))
            .expect("the busy block produces");
        let carried = crate::block::credit_set_iter(&blk.credit_set, crate::block::credit_seal_key(&blk.header, blk.cover_key.as_ref()).as_ref(), &blk.wide_objects).expect("the carried set parses");
        assert_eq!(carried.len(), 5, "PRECONDITION: all five justifiers ride, each with its subject");
        let seq = crate::node::Node::da_record_id_for_block(&blk.id(), 0);
        let real_concat: Vec<u8> = reals.concat();
        assert_eq!(blk.output_notes, real_concat, "PRECONDITION: the block's reals are exactly the five notes");

        // 1. CALIBRATION — with the payloads, the attack regenerates node_a's own record exactly.
        let record = node_a.da_record_notes(seq).expect("node_a holds its own block's record");
        let key = node_a.cover_key_of(seq);
        assert_eq!(
            assemble_fixed_note_payload(&real_concat, seq, &key),
            record,
            "CALIBRATION: fed the real notes AND the holder's key, the regeneration reproduces the record — every cover slot named"
        );

        // 2. No ciphertext byte on the wire — and node_b, the attacker, grafts exactly these bytes.
        let wire = postcard::to_allocvec(&blk).expect("the block encodes");
        for (i, note) in reals.iter().enumerate() {
            let window = &note[32..96];
            assert!(
                blk.output_notes.windows(window.len()).any(|w| w == window),
                "CALIBRATION: the search finds note {i}'s ciphertext where it is"
            );
            assert!(
                !wire.windows(window.len()).any(|w| w == window),
                "⛔⛔⛔ note {i}'s CIPHERTEXT rides the block wire — the regeneration attack's secret input"
            );
        }
        let received: crate::block::Block = postcard::from_bytes(&wire).expect("node_b decodes the wire block");
        let outcome = node_b.ingest_block(received, 9_000);
        assert!(
            matches!(outcome, crate::relay::RelayOutcome::Added(_)),
            "PRECONDITION: node_b grafts the wire block — the attacker holds all a peer is sent: {outcome:?}"
        );
        for (i, note) in reals.iter().enumerate() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&note[..32]);
            assert!(
                !node_b.holds_record_with_cm(&cm),
                "⛔⛔⛔ node_b recorded note {i} from the WIRE block alone — its payload crossed the wire"
            );
        }

        // 3. The attacker's best input from the wire: every note field the carried set exposes.
        let exposed: Vec<u8> = carried
            .iter()
            .filter_map(|e| crate::chain_object::carried_note_payloads(e))
            .flatten()
            .flatten()
            .collect();
        assert_eq!(
            exposed.len(),
            5 * crate::chain_object::NOTE_REF_BYTES,
            "the wire exposes exactly one 64-byte reference per credited note, nothing wider"
        );
        // §20.2: the attacker holds what the wire exposes and the one public key (the idle key) — never the producer's draw.
        assert_ne!(
            record_cover_secret(seq, &idle_cover_key(seq)),
            record_cover_secret(seq, &key),
            "⛔⛔⛔ the public key reproduces the record's cover secret"
        );
        assert_ne!(
            assemble_fixed_note_payload(&exposed, seq, &idle_cover_key(seq)),
            record,
            "⭐⭐⭐ the record regenerates from what the wire exposes"
        );
        assert_ne!(
            assemble_fixed_note_payload(&real_concat, seq, &idle_cover_key(seq)),
            record,
            "⭐⭐⭐ even the real notes regenerate the record without the holder's key"
        );
        eprintln!(
            "[db224] busy block on the wire: {} B total, credit_set {} B for 5 carried credits \
             ({} B per carriage), 0 ciphertext bytes",
            wire.len(),
            blk.credit_set.len(),
            blk.credit_set.len() / 5
        );
    }

    /// ⭐⭐⭐ DB-350 — THE ASK UNIVERSE, DERIVED. A which-item query is a surface: the peer that receives it views it.
    /// Every `want_*` door a wallet-facing RPC handler calls turns a wallet's selector into such an ask, so each must
    /// name the censused `Ask::` surface it raises. Read out of `src/rpc_http.rs` itself (the handler half), the way the
    /// block and transaction universes are read out of their structs: a new door fails here until what the peer learns
    /// is written down, and the retired by-commitment door cannot come back silently.
    /// CALIBRATION: the check fires on a synthetic handler that calls the retired door, and on an unmapped door.
    #[test]
    fn every_wallet_facing_want_door_is_in_the_census() {
        // TWO-PARTY-REVIEWED: a source census over the RPC handlers — the two parties this surface faces (the asking node
        // and the peer that views its ask) are what the register's answers describe; `db350_cm_ask_privacy_tests` drives
        // the ask between two parties and measures what the peer received.
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/rpc_http.rs"))
            .expect("the rpc module is readable");
        let doors = want_doors(rpc_handler_half(&src));
        for known in ["want_record_at_id", "want_record_at_ordinal", "want_account_bucket"] {
            assert!(doors.contains(known), "calibration: the door reader must see `{known}` (found {doors:?})");
        }
        let reopened = format!("{}\n        g.node_mut().want_record_by_cm(cm);\n", rpc_handler_half(&src));
        assert!(
            want_door_gaps(&reopened).iter().any(|g| g.contains("want_record_by_cm")),
            "CALIBRATION: a handler calling the retired by-commitment door must be caught"
        );
        let unmapped = format!("{}\n        g.node_mut().want_record_by_nullifier(nf);\n", rpc_handler_half(&src));
        assert!(
            want_door_gaps(&unmapped).iter().any(|g| g.contains("want_record_by_nullifier")),
            "CALIBRATION: a door with no censused ask must be caught"
        );
        let gaps = want_door_gaps(&src);
        assert!(gaps.is_empty(), "⛔⛔⛔ THE WALLET-FACING ASK UNIVERSE IS NOT CENSUSED:\n  {}", gaps.join("\n  "));
        let universe = census_universe_gaps();
        assert!(!universe.iter().any(|g| g.contains("want_")), "the readiness universe check agrees: {universe:?}");
    }

    /// Every surface answers all four, or is filed open with a name.
    #[test]
    fn every_observable_surface_answers_all_four() {
        let open: Vec<String> = SURFACES
            .iter()
            .filter(|s| !s.is_closed() && !FILED_OPEN.contains(&s.name))
            .map(|s| format!("{} — {}", s.name, s.gaps().join(" · ")))
            .collect();
        assert!(
            open.is_empty(),
            "⛔⛔⛔ {} OBSERVABLE SURFACE(S) LEAK AND ARE NOT FILED:\n  {}",
            open.len(),
            open.join("\n  ")
        );
        // ⛔ A STALE FILING IS A DEFECT, NOT A SPARE: it counts a closed surface as open on R5, and it exempts the row's
        // `Constant` claim from the shape probe. MEASURED 2026-10-24: `Block::output_notes` and `Block::pow_proof` were
        // filed while answering all four, and the real leak they stood for had no row.
        let stale: Vec<&str> = FILED_OPEN
            .iter()
            .filter(|f| SURFACES.iter().find(|s| s.name == **f).is_none_or(Surface::is_closed))
            .copied()
            .collect();
        assert!(
            stale.is_empty(),
            "⛔⛔⛔ FILED_OPEN names {} surface(s) with no row or a row that answers all four: {stale:?}",
            stale.len()
        );
        for s in SURFACES.iter().filter(|s| FILED_OPEN.contains(&s.name)) {
            eprintln!("[privacy] FILED OPEN: {} — {}", s.name, s.gaps().join(" · "));
        }
        eprintln!("[privacy] {} surfaces censused, {} filed open", SURFACES.len(), FILED_OPEN.len());
    }

    /// ⭐⭐⭐ THE FIFTH AXIS — **RECOVERABILITY**. A CONSTANT SHAPE IS NOT A HIDDEN COUNT.
    ///
    /// ⛔⛔⛔ WHY THIS EXISTS, AND IT INVALIDATES A FIX THIS MODULE ALMOST SHIPPED. §BX measured
    /// `Block::output_notes` publishing the real note count through its LENGTH, and the obvious repair —
    /// send the assembled 256-unit shape instead — remeasured at **295,168 B on quiet and busy alike,
    /// 0 of 12 surfaces reading activity**. Four axes green. It was reverted only because it cost speed.
    ///
    /// ⭐ IT WOULD NOT HAVE CLOSED THE LEAK EITHER WAY. `cover::strip_fixed_note_payload_det` INVERTS the
    /// constant shape: reals are a prefix, unit `i >= k` is `cover_note_det(block_cover_secret(reals, seq), i)`,
    /// and the secret hashes the reals LAST — so one streaming pass over the payload recovers `k` exactly,
    /// in ~2 ms, from the payload and `seq` ALONE. Both are in the hands of every peer that fetches the
    /// record. The node calls it on purpose (it is what keeps storage at the reals, not 256x), and that same
    /// inversion is available to anyone holding the bytes.
    ///
    /// ⇒ **A SCALE CANNOT SEE INVERTIBILITY.** §BX's own lesson was that a census of declared answers
    /// cannot see a shape leak, and only measurement can. The same sentence applies one level up: a
    /// measurement of LENGTH cannot see a leak that survives every length being equal. So the axis is
    /// measured here, on the construction itself, rather than declared per surface — the cover's whole
    /// claim is *"you cannot count"*, and this asks exactly that.
    ///
    /// ⛔ WHAT THIS DOES **NOT** SAY. The cover is not pointless: it still hides the count from anyone
    /// holding only the 256 LEAF COMMITMENTS (a light client, a DA sampler, a public-RPC observer), which
    /// is what `assemble_fixed_note_payload_det`'s doc actually claims. What it does not do is hide the
    /// count from a PEER, and the digital-cash cardinal says "as any node".
    ///
    /// This is a MEASUREMENT kept green, not a red pin (§AH: a pin that cannot go green stops being a pin).
    /// The flip condition is stated in the assertion: when a payload holder can no longer recover `k`, the
    /// `is_some()` goes false and this test says so.
    /// ⭐ THE RECOVERABILITY AXIS ON THE BLOCK SIDECARS (§POLES, 2026-10-25). `bond_set`, `dir_set` and `credit_set`
    /// were declared closed because every block's sidecar is 16,384 B. This asks the cover's real question — can a
    /// holder of the bytes count the entries? — of the exact pad the producer runs (`pad_sidecar_to_constant`) and
    /// the exact keyless walk every ingester runs (`sidecar_real_len`). A measurement kept green; it flips (and the
    /// three rows may leave FILED_OPEN) only when the count can no longer be recovered without a secret.
    /// ⭐ THE GOSSIPED TRANSACTION'S SHAPE, MEASURED (2026-10-28): two classes of four honest spends that differ ONLY in
    /// their amounts (999_999_000 + 1_000 vs 500_000_000 + 500_000_000) are weighed field by field on the wire, with the
    /// same-amount spends as the control. No field is stable inside a class and different between them, and every
    /// solve-noise field (the stamp's varint) spreads over the same widths in both classes — the `Shape::Constant` claim each
    /// `PqTx::*` register row makes. The field list is read off the struct itself, so a new field fails this pin until it
    /// is weighed. TWO-PARTY-REVIEWED: a source + shape census; the register's cross-node pins exercise the transaction.
    #[test]
    fn every_gossiped_transaction_field_has_one_shape_per_class_whatever_the_amount() {
        use crate::mempool::PqTx;
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mempool.rs")).expect("the mempool module is readable");
        let fields = pqtx_public_fields(&src);
        let weigh = |t: &PqTx| -> Vec<(&'static str, usize)> {
            let w = |b: Vec<u8>| b.len();
            vec![
                ("id", w(postcard::to_allocvec(&t.id).unwrap_or_default())),
                ("blob", w(postcard::to_allocvec(&t.blob).unwrap_or_default())),
                ("weight", w(postcard::to_allocvec(&t.weight).unwrap_or_default())),
                ("nullifiers", w(postcard::to_allocvec(&t.nullifiers).unwrap_or_default())),
                ("pow_stamp", w(postcard::to_allocvec(&t.pow_stamp).unwrap_or_default())),
                ("note_clues", w(postcard::to_allocvec(&t.note_clues).unwrap_or_default())),
                ("account_targets", w(postcard::to_allocvec(&t.account_targets).unwrap_or_default())),
                ("output_notes", w(postcard::to_allocvec(&t.output_notes).unwrap_or_default())),
                ("stake_notes", w(postcard::to_allocvec(&t.stake_notes).unwrap_or_default())),
                ("bond_notes", w(postcard::to_allocvec(&t.bond_notes).unwrap_or_default())),
                ("nullifier_witnesses", w(postcard::to_allocvec(&t.nullifier_witnesses).unwrap_or_default())),
                ("nullifier_absence", w(postcard::to_allocvec(&t.nullifier_absence).unwrap_or_default())),
                ("membership_carrier", w(postcard::to_allocvec(&t.membership_carrier).unwrap_or_default())),
                ("membership_leaf_commit", w(postcard::to_allocvec(&t.membership_leaf_commit).unwrap_or_default())),
                ("membership_tip", w(postcard::to_allocvec(&t.membership_tip).unwrap_or_default())),
                ("membership_folded_through", w(postcard::to_allocvec(&t.membership_folded_through).unwrap_or_default())),
                ("spend_or_decoy", w(postcard::to_allocvec(&t.spend_or_decoy).unwrap_or_default())),
                ("member_carrier", w(postcard::to_allocvec(&t.member_carrier).unwrap_or_default())),
                ("member_tuple", w(postcard::to_allocvec(&t.member_tuple).unwrap_or_default())),
            ]
        };
        let mut node = crate::node::tests::testnet_party_with_fold_depth(0);
        node.arm_template_double_for_test();
        // ⭐ THE CONTROL IS THE WHOLE INSTRUMENT (the block probe's own rule, `activity_probe_blocks`): a field whose
        // width wobbles between two spends of the SAME amounts is wobbling on its own — the anti-spam stamp is a solve
        // counter, a different varint width on different solves — and that is NOISE, not a readout. A field LEAKS the
        // amount when it is stable inside each amount class and moves between them. Four spends per class.
        let class_a: Vec<_> = (0..4u64)
            .map(|i| weigh(&crate::node::tests::honest_spend_tx_with_values_for_test(&mut node, &mut [], 7_701 + 2 * i, 999_999_000, 1_000)))
            .collect();
        let class_b: Vec<_> = (0..4u64)
            .map(|i| weigh(&crate::node::tests::honest_spend_tx_with_values_for_test(&mut node, &mut [], 7_702 + 2 * i, 500_000_000, 500_000_000)))
            .collect();
        let wa = class_a[0].clone();
        let weighed: BTreeSet<String> = wa.iter().map(|(n, _)| n.to_string()).collect();
        let unweighed: Vec<&String> = fields.difference(&weighed).collect();
        assert!(unweighed.is_empty(), "⛔ gossiped transaction field(s) this census does not weigh: {unweighed:?}");
        // DIGITAL-CASH-PRIVACY-REVIEWED: byte WIDTHS of test-built spends — no amount, note, key or owner.
        eprintln!("[t1-tx-shape] class A: {class_a:?}\n[t1-tx-shape] class B: {class_b:?}");
        let widths = |class: &[Vec<(&'static str, usize)>], k: usize| -> BTreeSet<usize> { class.iter().map(|w| w[k].1).collect() };
        let (mut moved, mut noisy) = (Vec::new(), Vec::new());
        for (k, (name, _)) in wa.iter().enumerate() {
            let (sa, sb) = (widths(&class_a, k), widths(&class_b, k));
            if sa.len() > 1 || sb.len() > 1 {
                noisy.push(format!("{name} {sa:?} / {sb:?}"));
            } else if sa != sb {
                moved.push(format!("{name} {sa:?} vs {sb:?}"));
            }
        }
        eprintln!("[t1-tx-shape] noise (moves between spends of the same amounts): {noisy:?}");
        assert!(moved.is_empty(), "⛔⛔⛔ a gossiped transaction field moved with the AMOUNT: {moved:?}");
        // A noisy field must be noisy in BOTH classes with overlapping widths — a field single-valued in one class and
        // spread in the other is a distribution that differs by amount, read as a leak, never as noise.
        for (k, (name, _)) in wa.iter().enumerate() {
            let (sa, sb) = (widths(&class_a, k), widths(&class_b, k));
            if sa.len() > 1 || sb.len() > 1 {
                assert!(
                    sa.intersection(&sb).next().is_some(),
                    "⛔⛔⛔ {name}'s width distribution differs by AMOUNT ({sa:?} vs {sb:?}) — not noise"
                );
            }
        }
        assert!(wa.iter().any(|(n, s)| *n == "output_notes" && *s > 0), "CALIBRATION: the spends carry their output notes");
    }

    #[test]
    fn a_padded_sidecar_is_measured_for_invertibility_back_to_the_real_count() {
        use crate::block::{pad_sidecar_to_constant, sidecar_real_len, SIDECAR_PADDED_BYTES};
        let cover_key = [0x5Au8; 32]; // the producer's secret; the inversion below never reads it
        let mut recovered = Vec::new();
        for reals in [1usize, 2, 7] {
            let mut side = Vec::new();
            for e in 0..reals {
                let body = vec![(e % 251) as u8 + 1; 300 + 97 * e]; // distinct lengths, like real objects
                side.extend_from_slice(&(body.len() as u32).to_le_bytes());
                side.extend_from_slice(&body);
            }
            pad_sidecar_to_constant(&mut side, &cover_key, b"MUSD-bond-pad");
            assert_eq!(side.len(), SIDECAR_PADDED_BYTES, "the wire LENGTH is the constant — that much IS true");
            // The observer's walk: bytes in, frame count out, no key.
            let end = sidecar_real_len(&side);
            let (mut off, mut n) = (0usize, 0usize);
            while off < end {
                off += 4 + u32::from_le_bytes(side[off..off + 4].try_into().unwrap()) as usize;
                n += 1;
            }
            recovered.push((reals, n));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: this prints counts of a LOCALLY SYNTHESISED fixture built in this test —
        // no chain object, note, tag, amount, key or owner is involved or printed.
        eprintln!("[privacy] recoverability of the 16,384 B sidecar pad from the bytes alone: {recovered:?}");
        for (reals, got) in &recovered {
            assert_eq!(
                got, reals,
                "⭐ THE SIDECAR PAD HAS BECOME NON-INVERTIBLE — re-measure bond_set / dir_set / credit_set against \
                 an observer and, if none can count, move them out of FILED_OPEN"
            );
        }
        // §21.1: an invertible count answers the shape question ONLY as `Shape::PublicActs` — the count of signed public
        // acts a published set already shows (bond_set, dir_set). Anything else is a leak this census must name.
        for f in ["Block::bond_set", "Block::dir_set"] {
            let public_acts = SURFACES.iter().any(|s| s.name == f && matches!(s.shape, Shape::PublicActs(_)));
            assert!(public_acts, "⛔ {f} is not a public-acts sidecar, but its padded sidecar is invertible to the real count (measured above)");
        }
        // ⭐ §22 — THE SEALED CREDIT SIDECAR: the same 1/2/7 objects sealed under a cover key. The OBSERVER's walk (no key):
        // the set opens None and the frame walk reads no entry. The HOLDER (the key): 1/2/7. The §20.2 shape, measured.
        use crate::block::{credit_set_iter, credit_set_iter_plain, credit_set_open, credit_set_seal, CREDIT_SET_SEALED_BYTES};
        let mut sealed_recovered = Vec::new();
        for reals in [1usize, 2, 7] {
            let objects: Vec<Vec<u8>> = (0..reals).map(|e| vec![(e % 251) as u8 + 1; 300 + 97 * e]).collect();
            let sealed = credit_set_seal(&objects, &cover_key).expect("1/2/7 small objects fit the width");
            assert_eq!(sealed.len(), CREDIT_SET_SEALED_BYTES, "the sealed width is the constant");
            let observer_open = credit_set_open(&sealed, None).is_some();
            let observer_walk = credit_set_iter_plain(&sealed).map(|v| v.len());
            let wrong_key = credit_set_iter(&sealed, Some(&[0x11u8; 32]), &[]).map(|v| v.len());
            let holder = credit_set_iter(&sealed, Some(&cover_key), &[]).map(|v| v.len());
            sealed_recovered.push((reals, observer_open, observer_walk, wrong_key, holder));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts of a LOCALLY SYNTHESISED fixture built in this test — no chain object.
        eprintln!("[privacy] §22 sealed credit sidecar (reals, observer opens, observer walk, wrong key, holder): {sealed_recovered:?}");
        for (reals, observer_open, observer_walk, wrong_key, holder) in &sealed_recovered {
            assert!(!observer_open, "⛔ §22: a keyless observer opened the sealed credit set ({reals} reals)");
            assert_ne!(*observer_walk, Some(*reals), "⛔ §22: the keyless frame walk recovered the real count {reals}");
            assert_eq!(*wrong_key, None, "⛔ §22: the wrong key opened the sealed credit set ({reals} reals)");
            assert_eq!(*holder, Some(*reals), "CALIBRATION: the holder reads exactly {reals} objects");
        }
        assert!(!FILED_OPEN.contains(&"Block::credit_set"), "§22: credit_set left FILED_OPEN on the measurement above");
        assert!(
            SURFACES.iter().any(|s| s.name == "Block::credit_set" && matches!(s.shape, Shape::Constant(_))),
            "§22: the register files credit_set Constant on the measurement above"
        );
    }

    /// §20.2 (2026-10-28) — THE COVER HAS BECOME NON-INVERTIBLE, as this measurement's own red text foresaw: the record's
    /// cover is keyed on its producer's COVER KEY (`record_cover_secret(seq, key)`, `header_seed(reals, key)`), held beside
    /// the reals and served to PEERS only. The node itself (a holder, with the key) still recovers the exact reals, so
    /// storage stays at the reals; a payload holder without the key — the one public key is the idle key — recovers
    /// nothing. The recoverability axis of §BX closes here; `s20_a_served_record_does_not_invert_to_its_real_count` pins it
    /// on a produced block.
    #[test]
    fn a_constant_shape_is_measured_for_invertibility_back_to_the_real_count() {
        use crate::cover::{assemble_fixed_note_payload, idle_cover_key, strip_fixed_note_payload, PQ_NOTE_BYTES};
        let seq: u64 = 0x5E9_u64; // any address; the inversion does not depend on which
        let key: crate::cover::CoverKey = crate::cover::fresh_cover_key(); // the producer's draw
        let mut recovered = Vec::new();
        for reals in [1usize, 2, 7] {
            let mut r = vec![0u8; reals * PQ_NOTE_BYTES];
            for (i, b) in r.iter_mut().enumerate() {
                *b = (i % 251) as u8 + 1; // non-zero, distinct — never a cover-shaped unit
            }
            let payload = assemble_fixed_note_payload(&r, seq, &key);
            assert_eq!(
                payload.len(),
                256 * PQ_NOTE_BYTES,
                "the wire shape is the protocol constant whatever the real count — that much IS true"
            );
            let holder = strip_fixed_note_payload(&payload, seq, &key).map(|b| b.len() / PQ_NOTE_BYTES);
            let observer = strip_fixed_note_payload(&payload, seq, &idle_cover_key(seq)).map(|b| b.len() / PQ_NOTE_BYTES);
            recovered.push((reals, holder, observer));
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: this prints counts of a LOCALLY SYNTHESISED fixture built in this
        // test — no chain note, tag, amount, key or owner is involved or printed.
        eprintln!("[privacy] recoverability of the 256-cover: (reals, the holder's strip, the public strip) = {recovered:?}");
        for (reals, holder, observer) in &recovered {
            assert_eq!(*holder, Some(*reals), "the node itself (the key's holder) must still recover the exact reals — storage stays at the reals");
            assert_eq!(*observer, None, "⛔ a payload holder WITHOUT the key recovered the real count — the cover is invertible again");
        }
        eprintln!(
            "[privacy] §BX recoverability axis CLOSED (§20.2): the constant 256-unit shape is NOT invertible from the \
             payload + seq alone; the count is recoverable only under the record's cover key, which a wallet route never serves."
        );
    }
}

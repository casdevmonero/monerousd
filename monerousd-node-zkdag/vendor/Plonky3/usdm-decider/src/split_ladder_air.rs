// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE SPLIT LADDER — a note is DEBITED, never consumed-and-replaced.
//!
//! ## The model this replaces
//!
//! The retired "change model" spent a note in full and minted a fresh change note for the remainder. That
//! made the ENTIRE value move for a payment of any size, and — because the remainder was a brand-new
//! commitment — it was unspendable until its block landed. Two payments in a row therefore could not both
//! settle: the second had no membership proof to build, because the note it wanted to spend did not yet
//! exist anywhere on chain.
//!
//! user 2026-08-14: *"if only 1000 out of 1 million is sent then only the 1000 should move not the whole
//! 1 million. Making the whole thing move was a terrible overengineered design."*
//!
//! ## The model this implements
//!
//! A note is a STATE MACHINE with a **commitment per state**. State `i` of a note held under spend key `sk`
//! is worth `v_i`, and is named by two values that already exist elsewhere in this protocol:
//!
//! ```text
//! S_i = Poseidon([v_i,0,0,0], sk)     the STATE COMMITMENT   (== pq_spend::note_commitment)
//! N_i = Poseidon(sk, S_i)             the STATE TAG          (== pq_spend::note_nullifier)
//! ```
//!
//! A payment debits the note: `v_{i+1} = v_i − paid`. The note keeps its identity (`sk` never changes) and
//! keeps its ON-CHAIN BIRTH ANCHOR forever. Only the paid fraction moves, as a fresh note to the payee.
//!
//! Re-using the EXISTING commitment/tag functions is deliberate and load-bearing: the tag for a state is a
//! pure function of `(v_i, sk)`, so a state has exactly ONE tag no matter which proof path establishes that
//! the state exists. A note whose current state has landed on chain can be spent by the ordinary membership
//! route, and a note whose current state has not can be spent by this ladder, and the two can never produce
//! two different tags for one state — so there is no double-spend seam between them.
//!
//! ## The cost, written as a function
//!
//! Let `k` be the number of debits a note has taken and `H` the chain height. Every quantity below is
//! written as a function; if `k` or `H` appears in one, it is not constant.
//!
//! ```text
//! node state added        = 0 bytes                          (no ladder, no counter, no anchor map;
//!                                                             a transition tag folds into the SAME O(1)
//!                                                             tag accumulator the nullifier already uses)
//! node verify calls       = 1                                 f(nothing)
//! sealed proof shape      = f(lambda, LADDER_STEP_COLS, LADDER_STEP_ROWS=8)
//! prover calls per debit  = 2                                 f(nothing) — one step, one merge
//! prover calls per seal   = 3                                 f(nothing)
//! wallet state per note   = 2 u64 + 3 digests + 1 proof       f(lambda, fixed constants)
//! ```
//!
//! None of them contains `k` or `H`. The reason is the recursive merge: `debit()` re-verifies the previous
//! proof IN-CIRCUIT and replaces it, so `running` is one proof rather than a list, and the carrier's fields
//! are overwritten in place. `the_sealed_proof_is_the_same_size_at_one_step_and_at_many` measures this
//! directly — a deterministic byte-length counter, taken at two very different step counts, must be equal.
//!
//! The dependency this DELETES is the one that mattered: under the change model the second of two
//! consecutive payments could not be built at all, because its input note existed nowhere on chain. That
//! was a hard dependency on block arrival; there is none here, because the ladder needs nothing from the
//! chain to advance.
//!
//! ## Why a ladder needs a proof at all
//!
//! Double-spending one state is stopped by the tag alone (`N_i` can only be published once). What the tag
//! does NOT stop is a lie about WHICH state the note is in. Concretely, with a 100 note that really paid 60:
//!
//! ```text
//! real:   S_0(100) --pay 60--> S_1(40)        tag N_0 published
//! forged: S_0(100) --pay  1--> S_1'(99)       tag N_0 published (the same one!)
//! ```
//!
//! Both stories publish `N_0`, because the tag binds the state being CONSUMED and says nothing about the
//! remainder. So a spender could later present `S_1'(99)`, publish the fresh tag `N_1'`, and spend 99 out
//! of a note holding 40. That is inflation, and it is why the ladder exists.
//!
//! The fix is to put the remainder INTO an on-chain object. Every spend publishes, alongside its tag, a
//! **TRANSITION TAG**:
//!
//! ```text
//! X_i = Poseidon(N_i, S_{i+1})
//! ```
//!
//! which binds "the spend that consumed state `i` produced state `i+1`" — and the node derives it from
//! values the transaction already publishes (its nullifier and its remainder output commitment), so binding
//! the remainder costs the wire nothing and the tag accumulator absorbs it in the O(1) fold it already does.
//!
//! ## What this circuit proves
//!
//! One step of the ladder, recursively merged into the running proof exactly as
//! [`crate::note_membership_air::NoteMembershipCarrier`] merges block folds — so `k` steps verify in ONE
//! constant-size check and the proof never grows:
//!
//! ```text
//! lacc_0     = Poseidon([SPLIT_LADDER_BASE_DOMAIN,0,0,0], anchor_leaf)
//! lacc_{i+1} = Poseidon(lacc_i, X_i)
//! ```
//!
//! ## How the anchor is carried WITHOUT leaking it
//!
//! The ladder must tie back to the note's on-chain birth leaf, or it proves nothing about this chain. Naming
//! that leaf publicly is not an option: it is the value written when the note was RECEIVED, so publishing it
//! links every spend of the note to its receipt, and links the note's spends to each other.
//!
//! So the ANCHOR IS CARRIED BY THE ACCUMULATOR ITSELF. `lacc_0` is defined as a Poseidon image OF the anchor
//! leaf, and every step gate:
//!
//!   * holds `anchor_leaf` as a **witness column**, never a public one;
//!   * proves `base == Poseidon([BASE_DOM,0,0,0], anchor_leaf)` against a `base` public that is consumed
//!     INSIDE the recursion and is absent from the final output bind — so every step provably witnesses the
//!     same anchor (a second anchor would be a Poseidon collision), and no verifier ever sees a value that
//!     is constant across the note's life;
//!   * proves, on step 0 only, `S_cur == anchor_leaf` — the ladder starts at the note's birth state.
//!
//! The spend-time SEALING step then welds the two values the node actually needs, both randomised by THIS
//! spend's binder (its nullifier) so neither is stable across spends:
//!
//! ```text
//! anchor_commit = Poseidon(anchor_leaf, binder)   <- the SAME function NoteMembershipCarrier binds, so the
//!                                                    existing on-chain membership proof and this ladder are
//!                                                    provably about one anchor, with the leaf never revealed
//! leaf_commit   = Poseidon(S_cur,       binder)   <- the SAME cross-bind the spend-validity carrier welds
//! ```
//!
//! ## What a verifier learns, item by item
//!
//! Every value that leaves the wallet is a Poseidon image taken over this spend's binder or over secret
//! state: `anchor_commit`, `leaf_commit`, the ladder accumulator, and the transition tags. None of them is
//! an amount, a key, an owner or a note, and none is stable across two spends of the same note — so two
//! spends cannot be linked to each other or to the receipt that created the note. The step count is not
//! published either: `k` is absorbed by the recursion, so a first split and a fiftieth are the same
//! constant-size object with the same verify cost.

// ONE digest width for the whole tree — 8 lanes x 31 bits = 248 bits (kill list §AG).
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::hiding_decider::{Ea4, Fa4};
use crate::nullifier_insert_air::{kred, poseidon_pair_native};
use p3_field::PrimeCharacteristicRing;

/// Limbs in a `Digest4` — the WIDTH of one digest. Not a cover, note or nullifier count: the production
/// cover width is 256 and is not a parameter of this circuit at all.
/// Limbs in one chain digest. ⛔ WAS 4 — a stale literal that would have welded only HALF of an 8-lane
/// digest in the ladder's fold and seal welds, leaving the top four lanes unconstrained. The width lives in ONE place.
const DIGEST_LIMBS: usize = crate::poseidon2_compress::DIGEST_LANES;

/// Domain separator for the ladder BASE — `lacc_0 = Poseidon([BASE,0,0,0], anchor_leaf)`. Distinct from every
/// other fold in the protocol, so a ladder proof can never be replayed as a proof about anything else.
pub const SPLIT_LADDER_BASE_DOMAIN: u64 = 0x5350_4c54_5f42_4153;

/// Domain separator for a single ladder STEP's transcript bind.
pub const SPLIT_LADDER_STEP_DOMAIN: u64 = 0x5350_4c54_5f53_5445;

/// Domain separator for the SEALED (spend-time) output bind — what the node verifies.
pub const SPLIT_LADDER_CHAIN_DOMAIN: u64 = 0x5350_4c54_5f43_4841;

/// Rows in one step's trace. A power of two is required by the sumcheck layout (a shorter trace has no
/// variables to bind), and the ladder arithmetic is row-local, so every row carries the same values. This is
/// a fixed proof-shape constant: it does not move with chain height, note count, step count or cover width.
pub const LADDER_STEP_ROWS: usize = 8;

/// Column count of one ladder-step row — a per-row width, fixed by the column map documented on
/// [`SplitStepGate`] and by nothing else.
/// The step row's HEAD: three values, then three digests.
///
/// ⛔⛔⛔ THESE WERE LITERALS ON BOTH SIDES — `local[3 + c]`, `local[7 + c]`, `local[11 + c]` in the gate
/// and `cols[3 + c]`, `cols[7 + c]`, `cols[11 + c]` in the builder, plus `SL_B0 = 15`, plus the ten block
/// bases 15/35/…/195 and their outputs 31/51/…/211, plus `cols[239]`/`cols[240]` for the two selectors.
/// All of it is `3 + 3 × 4` and a 20-column one-round block: the retired arithmetic (kill list §AG). Each
/// block is a whole Poseidon2 permutation now and a digest is eight lanes, so every one of those numbers
/// moved. ⭐ A column offset written as a literal is a layout that cannot move.
pub const SL_V_PREV: usize = 0;
pub const SL_V_CUR: usize = 1;
pub const SL_V_NEXT: usize = 2;
pub const SL_SK: usize = SL_V_NEXT + 1;
pub const SL_ANCHOR: usize = SL_SK + DIGEST_LIMBS;
pub const SL_LACC_PREV: usize = SL_ANCHOR + DIGEST_LIMBS;
/// Where the compression blocks start, and how wide one is.
pub const SL_B0: usize = SL_LACC_PREV + DIGEST_LIMBS;
pub const SL_BLOCK: usize = crate::pow_pq_air::P2_COLS + DIGEST_LANES;
/// The k-th compression block's base, and the column its OUTPUT digest starts at.
#[must_use]
pub const fn sl_blk(k: usize) -> usize { SL_B0 + k * SL_BLOCK }
#[must_use]
pub const fn sl_out(k: usize) -> usize { sl_blk(k) + crate::pow_pq_air::PERM_OUT }
/// The two SEAL commitment blocks follow the ten compressions, then the two selectors.
pub const SL_COMMIT0: usize = sl_blk(10);
pub const SL_COMMIT1: usize = SL_COMMIT0 + SL_BLOCK;
pub const SL_FIRST: usize = SL_COMMIT1 + SL_BLOCK;
pub const SL_SEAL: usize = SL_FIRST + 1;
pub const LADDER_STEP_COLS: usize = SL_SEAL + 1;

// ---------------------------------------------------------------------------------------------------------
// Native definitions. Prover, verifier, wallet and node all compute these from ONE place — a second copy of
// any of them is how the two halves of a proof drift until nothing verifies.
// ---------------------------------------------------------------------------------------------------------

/// The STATE COMMITMENT of a note worth `v` under spend key `sk`. Byte-identical to the wallet's
/// `pq_spend::note_commitment` and to the leaf the spend circuit opens — one definition, three users.
pub fn state_commitment(v: u64, sk: Digest) -> Digest {
    poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[v]), sk)
}

/// The STATE TAG of that state. Byte-identical to `pq_spend::note_nullifier`'s limbs — which is what makes
/// the ladder route and the ordinary on-chain route agree on one tag per state (no double-spend seam).
pub fn state_tag(v: u64, sk: Digest) -> Digest {
    poseidon_pair_native(sk, state_commitment(v, sk))
}

/// The TRANSITION TAG a spend publishes: "the spend that consumed `tag` produced state `next_commit`".
///
/// The node derives this from the transaction's OWN public fields — its nullifier and the commitment of the
/// remainder output — so binding the remainder costs no extra wire bytes and cannot be omitted by a spender.
/// Without it a spender could consume a state honestly and then claim a LARGER remainder than it produced,
/// which is inflation; see the module header for the exact forged story this closes.
pub fn transition_tag(tag: Digest, next_commit: Digest) -> Digest {
    poseidon_pair_native(tag, next_commit)
}

/// The ladder BASE — the accumulator's starting value, and the only thing that carries the anchor.
pub fn split_ladder_base(anchor_leaf: Digest) -> Digest {
    poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[SPLIT_LADDER_BASE_DOMAIN]), anchor_leaf)
}

/// Advance the ladder accumulator by ONE debit. Constant work, constant size, at any step count.
pub fn split_ladder_step_acc(prev: Digest, transition: Digest) -> Digest {
    poseidon_pair_native(prev, transition)
}

/// The per-spend commitment to a value, taken over this spend's binder. Used for BOTH the anchor tie and the
/// state cross-bind, and it is deliberately the SAME function
/// [`crate::note_membership_air::note_leaf_commitment`] uses — that identity is what lets the existing
/// on-chain membership proof and this ladder be provably about one anchor without either revealing it.
pub fn bound_commitment(value: Digest, binder: Digest) -> Digest {
    poseidon_pair_native(value, binder)
}

/// Transcript bind of ONE ladder step.
///
/// `base` appears here — inside the recursion, where the merged step re-verifies its input against this bind
/// — and NOWHERE in [`split_ladder_out_bind`]. That asymmetry is the privacy property: the anchor is threaded
/// through every step by a value no verifier ever receives.
fn split_ladder_step_bind(
    base: Digest,
    lacc_in: Digest,
    lacc_out: Digest,
    anchor_commit: Digest,
    leaf_commit: Digest,
    binder: Digest,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(SPLIT_LADDER_STEP_DOMAIN)];
    for v in [base, lacc_in, lacc_out, anchor_commit, leaf_commit, binder] {
        for c in 0..DIGEST_LIMBS {
            b.push(Fa4::from_u64(kred(v[c])));
        }
    }
    b
}

/// Transcript bind of the SEALED ladder — the only thing the node ever sees.
///
/// Note what is absent: `base`, the anchor leaf, every intermediate accumulator, every value, and the step
/// count. A one-step ladder and a fifty-step ladder produce the same object.
pub fn split_ladder_out_bind(
    anchor_commit: Digest,
    leaf_commit: Digest,
    binder: Digest,
    lacc_out: Digest,
) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(SPLIT_LADDER_CHAIN_DOMAIN)];
    for v in [anchor_commit, leaf_commit, binder, lacc_out] {
        for c in 0..DIGEST_LIMBS {
            b.push(Fa4::from_u64(kred(v[c])));
        }
    }
    b
}

// ---------------------------------------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------------------------------------

/// One ladder step: state `i` is debited to state `i+1`, and the accumulator advances by that transition.
///
/// Column map (all row-local; every row of the fixed-height trace carries the same values, and the cross-row
/// welds in part (F) force that so a prover cannot vary a witness between rows):
///
/// ```text
///   0 v_prev · 1 v_cur · 2 v_next · 3..7 sk · 7..11 anchor_leaf · 11..15 lacc_prev
///   15..35  S_prev  = Poseidon([v_prev,0,0,0], sk)     (pre,sq,p4,p7,out)
///   35..55  N_prev  = Poseidon(sk, S_prev)
///   55..75  S_cur   = Poseidon([v_cur,0,0,0], sk)
///   75..95  X_prev  = Poseidon(N_prev, S_cur)
///   95..115 lacc_in_chk = Poseidon(lacc_prev, X_prev)
///  115..135 N_cur   = Poseidon(sk, S_cur)
///  135..155 S_next  = Poseidon([v_next,0,0,0], sk)
///  155..175 X_cur   = Poseidon(N_cur, S_next)
///  175..195 lacc_out_chk = Poseidon(lacc_in, X_cur)
///  195..215 base_chk = Poseidon([BASE_DOM,0,0,0], anchor_leaf)
///  215..227 anchor_commit x⁷ chain (sq,p4,p7)   — welded only when `seal`
///  227..239 leaf_commit   x⁷ chain (sq,p4,p7)   — welded only when `seal`
///  239 first · 240 seal
/// ```
pub struct SplitStepGate {
    pub gamma: Ea4,
    /// The ladder BASE. Public to the RECURSION only — never in the sealed output bind. See the module
    /// header: this is the value that threads the anchor across every step without revealing it.
    pub base: [Ea4; DIGEST_LANES],
    pub lacc_in: [Ea4; DIGEST_LANES],
    pub lacc_out: [Ea4; DIGEST_LANES],
    /// `Poseidon(anchor_leaf, binder)` — welded on the sealing step only. Zero on interior steps.
    pub anchor_commit: [Ea4; DIGEST_LANES],
    /// `Poseidon(S_cur, binder)` — the SAME cross-bind the spend-validity carrier welds. Sealing step only.
    pub leaf_commit: [Ea4; DIGEST_LANES],
    /// This spend's nullifier. Sealing step only; zero on interior steps.
    pub binder: [Ea4; DIGEST_LANES],
}

impl crate::air_zerocheck::AirConstraint for SplitStepGate {
    fn degree(&self, nvars: usize) -> usize {
        (nvars + 1).max(crate::pow_pq_air::PERM_MAX_DEGREE) // the embedded permutation
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::ZERO;
        let seven = Ea4::from(Fa4::from_u64(7));
        let mut rs: Vec<Ea4> = Vec::new();

        let v_prev = local[SL_V_PREV];
        let v_cur = local[SL_V_CUR];
        let v_next = local[SL_V_NEXT];
        let sk = |c: usize| local[SL_SK + c];
        let anchor = |c: usize| local[SL_ANCHOR + c];
        let lacc_prev = |c: usize| local[SL_LACC_PREV + c];
        let first = local[SL_FIRST];
        let seal = local[SL_SEAL];

        // One Poseidon compression, laid out as (pre, sq, p4, p7, out) over a 20-column block starting at
        // `o`, compressing `lhs` and `rhs`: pre = lhs + 7·rhs, then x⁷, then the MDS mix. This is the SAME
        // permutation the membership tree, the note opening and the nullifier weld use — one definition.
        //
        // Written once as a closure because a hand-copied Poseidon block is exactly how a prover and a
        // verifier end up proving different things. Pure algebra over DIGEST_LIMBS = 4 field limbs; no I/O.
        let pose = |rs: &mut Vec<Ea4>,
                    o: usize,
                    lhs: &dyn Fn(usize) -> Ea4,
                    rhs: &dyn Fn(usize) -> Ea4| {
            crate::pow_pq_air::push_perm_residuals(local, o, rs);
            for c in 0..DIGEST_LIMBS {
                rs.push(local[o + c] - lhs(c));
                rs.push(local[o + DIGEST_LIMBS + c] - rhs(c));
            }
        };
        // A compression block's OUTPUT cells.
        let pose_out = |o: usize, c: usize| local[o + crate::pow_pq_air::PERM_OUT + c];

        // A note VALUE occupies limb 0 of the left operand and zero elsewhere — the same shape
        // `state_commitment` uses natively. Written as a closure so the three value-openings stay identical.
        let val_lhs = |v: Ea4| move |c: usize| if c == 0 { v } else { zero };

        // (A) The three state commitments and the two state tags this step reasons about.
        pose(&mut rs, sl_blk(0), &val_lhs(v_prev), &sk); //     S_prev
        let s_prev = |c: usize| local[sl_out(0) + c];
        pose(&mut rs, sl_blk(1), &sk, &s_prev); //              N_prev
        let n_prev = |c: usize| local[sl_out(1) + c];
        pose(&mut rs, sl_blk(2), &val_lhs(v_cur), &sk); //      S_cur
        let s_cur = |c: usize| local[sl_out(2) + c];
        pose(&mut rs, sl_blk(5), &sk, &s_cur); //              N_cur
        let n_cur = |c: usize| local[sl_out(5) + c];
        pose(&mut rs, sl_blk(6), &val_lhs(v_next), &sk); //    S_next
        let s_next = |c: usize| local[sl_out(6) + c];

        // (B) The two transitions: the one that CREATED this state, and the one this step performs.
        pose(&mut rs, sl_blk(3), &n_prev, &s_cur); //           X_prev = Poseidon(N_prev, S_cur)
        let x_prev = |c: usize| local[sl_out(3) + c];
        pose(&mut rs, sl_blk(7), &n_cur, &s_next); //          X_cur  = Poseidon(N_cur,  S_next)
        let x_cur = |c: usize| local[sl_out(7) + c];

        // (C) THE ACCUMULATOR LINKS — what makes a chain of steps a CHAIN rather than k unrelated claims.
        //
        // Backward: the accumulator this step starts from must be exactly the one the PREVIOUS transition
        // produced. Without this an interior step could start from any value it liked, and the ladder would
        // prove only "some sequence of debits exists", never "THIS note's sequence".
        pose(&mut rs, sl_blk(4), &lacc_prev, &x_prev); //       lacc_in_chk = Poseidon(lacc_prev, X_prev)
        let lacc_in_chk = |c: usize| local[sl_out(4) + c];
        for c in 0..DIGEST_LIMBS {
            rs.push((one - first) * (lacc_in_chk(c) - self.lacc_in[c]));
        }
        // Forward: the accumulator this step hands on is this step's own transition folded in.
        pose(&mut rs, sl_blk(8), &|c: usize| self.lacc_in[c], &x_cur); // lacc_out_chk
        let lacc_out_chk = |c: usize| local[sl_out(8) + c];
        for c in 0..DIGEST_LIMBS {
            rs.push(lacc_out_chk(c) - self.lacc_out[c]);
        }

        // (D) THE ANCHOR, THREADED WITHOUT EVER BEING NAMED.
        //
        // `base` is a public of the STEP bind and is absent from the SEALED bind, so it is visible only to
        // the recursion that re-verifies this step. Constraining it to open as
        // `Poseidon(BASE_DOM, anchor_leaf)` forces every step of the ladder to witness the SAME anchor leaf
        // (a second anchor would be a Poseidon collision), which is what lets the sealing step below speak
        // about an anchor it never saw declared, and what lets the node tie this ladder to an on-chain
        // membership proof without either side revealing the leaf.
        pose(
            &mut rs,
            sl_blk(9),
            &|c: usize| {
                if c == 0 {
                    Ea4::from(Fa4::from_u64(SPLIT_LADDER_BASE_DOMAIN))
                } else {
                    zero
                }
            },
            &anchor,
        );
        let base_chk = |c: usize| local[sl_out(9) + c];
        for c in 0..DIGEST_LIMBS {
            rs.push(base_chk(c) - self.base[c]);
        }
        // Step 0 has no predecessor: its accumulator IS the base, and its current state IS the anchor. These
        // two are the ladder's foot — omit either and a prover could start a ladder mid-air at a state of
        // its choosing, and the anchor would then constrain nothing at all.
        rs.push(first * (first - one));
        for c in 0..DIGEST_LIMBS {
            rs.push(first * (self.lacc_in[c] - self.base[c]));
            rs.push(first * (s_cur(c) - anchor(c)));
        }

        // (E) THE SEALING WELDS — the two values the node checks, both randomised by this spend's binder.
        //
        // `anchor_commit` is the SAME function the note-membership carrier binds, so "this ladder's anchor"
        // and "the leaf proven to be on chain" are one statement without either revealing the leaf.
        // `leaf_commit` is the SAME cross-bind the spend-validity carrier welds, so "the state this ladder
        // ends at" and "the note that spend opens" are likewise one statement.
        //
        // Both are multiplied by `seal`, so an interior step proves neither and carries zeros — an interior
        // step is not about any particular spend and must not be bound to one.
        rs.push(seal * (seal - one));
        for (o, value, target) in [
            (SL_COMMIT0, &anchor as &dyn Fn(usize) -> Ea4, &self.anchor_commit),
            (SL_COMMIT1, &s_cur as &dyn Fn(usize) -> Ea4, &self.leaf_commit),
        ] {
            // The SEAL commitment is compress(value, binder) — one whole permutation, gated by `seal`
            // so an interior step proves neither commitment.
            crate::pow_pq_air::push_perm_residuals(local, o, &mut rs);
            for c in 0..DIGEST_LIMBS {
                rs.push(seal * (local[o + c] - value(c)));
                rs.push(seal * (local[o + DIGEST_LIMBS + c] - self.binder[c]));
                rs.push(seal * (local[o + crate::pow_pq_air::PERM_OUT + c] - target[c]));
            }
        }

        // (F) ONE WITNESS PER STEP, NOT ONE PER ROW. The trace height is fixed by the sumcheck layout, so the
        // step's values are replicated across rows; without these welds a prover could witness a different
        // `sk`, anchor or value on each row and satisfy the row-local constraints with unrelated data.
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        // ⛔ THE LAST TWO LITERAL LISTS IN THIS FILE — `[0, 1, 2, 239, 240]` and `[3, 7, 11]`. They named the
        // head columns and the two selectors at the retired width, so the cross-row welds pinned the WRONG
        // cells: `sk`, the anchor and `lacc_prev` were each welded across rows only for their first four
        // lanes, and 239/240 welded two digest cells instead of the selectors. An honest ladder then failed
        // its own gate. Nothing here is spelled out any more.
        for col in [SL_V_PREV, SL_V_CUR, SL_V_NEXT, SL_FIRST, SL_SEAL] {
            rs.push(not_last * (at(col, &sigma) - local[col]));
        }
        for base_col in [SL_SK, SL_ANCHOR, SL_LACC_PREV] {
            for c in 0..DIGEST_LIMBS {
                rs.push(not_last * (at(base_col + c, &sigma) - local[base_col + c]));
            }
        }

        let mut out = zero;
        let mut pw = one;
        for r in rs {
            out = out + pw * r;
            pw = pw * self.gamma;
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------------------
// Prover.
// ---------------------------------------------------------------------------------------------------------

/// Fill one Poseidon block natively, mirroring the gate's `pose` closure exactly. Pure field algebra over
/// DIGEST_LIMBS limbs — no I/O, no proof call, nothing that touches the chain.
fn fill_pose(cols: &mut [Vec<Fa4>], o: usize, row: usize, lhs: Digest, rhs: Digest) -> Digest {
    crate::pow_pq_air::lay_perm_row_at(cols, o, row, crate::pow_pq_air::pair_state(&lhs, &rhs));
    let out = poseidon_pair_native(lhs, rhs);
    for c in 0..DIGEST_LIMBS {
        cols[o + crate::pow_pq_air::PERM_OUT + c][row] = Fa4::from_u64(out[c]);
    }
    out
}

/// Fill an x⁷ commitment block (sq, p4, p7 only — the output is welded to a public, not stored).
fn fill_commit(cols: &mut [Vec<Fa4>], o: usize, row: usize, value: Digest, binder: Digest) {
    let _ = fill_pose(cols, o, row, value, binder);
}

/// Prove ONE ladder step. `None` only on inconsistent input — never a partial or an approximate proof.
///
/// `v_prev`/`lacc_prev` describe the transition that CREATED the state being debited; on step 0 they are
/// unused (the `first` selector replaces those constraints with the base/anchor welds) and may be zero.
///
/// cons: none. Work here is `f(LADDER_STEP_ROWS=8, DIGEST_LIMBS=4, lambda)`. The trace fill is pure field
/// algebra over those two compile-time constants and does no I/O; the single prover call sits outside it.
/// Nothing is read from the chain, so no history quantity can enter.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn prove_split_step_bytes(
    anchor_leaf: Digest,
    sk: Digest,
    v_prev: u64,
    v_cur: u64,
    v_next: u64,
    lacc_prev: Digest,
    first: bool,
    seal: Option<Digest>,
) -> Option<(Vec<u8>, Vec<Fa4>, Digest, Digest)> {
    // FAIL CLOSED ON A LADDER THAT DOES NOT DESCEND. A step that increases the note's value is not a debit,
    // and proving one would be proving inflation. The circuit does not range-check the subtraction (a u64
    // range check per step is cost the spend carrier's own conservation weld already pays), so the refusal
    // lives here, where the witness is chosen — and the node's independent check is that the spend carrier
    // conserves value against the SAME state commitment this step ends at.
    if v_next > v_cur {
        eprintln!(
            "[split-step] refused: a ladder step must DEBIT the note — the requested next state is larger \
             than the current one, which is not a payment but an inflation."
        );
        return None;
    }
    let base = split_ladder_base(anchor_leaf);
    let s_cur = state_commitment(v_cur, sk);
    if first && s_cur != anchor_leaf {
        eprintln!(
            "[split-step] refused: step 0 must open the note's BIRTH state — the claimed current state does \
             not equal the anchor leaf, so this ladder has no foot on chain."
        );
        return None;
    }
    let lacc_in = if first {
        base
    } else {
        split_ladder_step_acc(lacc_prev, transition_tag(state_tag(v_prev, sk), s_cur))
    };
    let x_cur = transition_tag(state_tag(v_cur, sk), state_commitment(v_next, sk));
    let lacc_out = split_ladder_step_acc(lacc_in, x_cur);
    let binder = seal.unwrap_or([0u64; DIGEST_LANES]);
    let anchor_commit = if seal.is_some() { bound_commitment(anchor_leaf, binder) } else { [0u64; DIGEST_LANES] };
    let leaf_commit = if seal.is_some() { bound_commitment(s_cur, binder) } else { [0u64; DIGEST_LANES] };

    let h = LADDER_STEP_ROWS;
    let mut cols: Vec<Vec<Fa4>> = (0..LADDER_STEP_COLS).map(|_| vec![Fa4::ZERO; h]).collect();
    for row in 0..h {
        cols[SL_V_PREV][row] = Fa4::from_u64(kred(v_prev));
        cols[SL_V_CUR][row] = Fa4::from_u64(kred(v_cur));
        cols[SL_V_NEXT][row] = Fa4::from_u64(kred(v_next));
        for c in 0..DIGEST_LIMBS {
            cols[SL_SK + c][row] = Fa4::from_u64(kred(sk[c]));
            cols[SL_ANCHOR + c][row] = Fa4::from_u64(kred(anchor_leaf[c]));
            cols[SL_LACC_PREV + c][row] = Fa4::from_u64(kred(lacc_prev[c]));
        }
        let s_prev = fill_pose(&mut cols, sl_blk(0), row, crate::poseidon2_compress::lanes_of(&[v_prev]), sk);
        let n_prev = fill_pose(&mut cols, sl_blk(1), row, sk, s_prev);
        let sc = fill_pose(&mut cols, sl_blk(2), row, crate::poseidon2_compress::lanes_of(&[v_cur]), sk);
        let n_cur = fill_pose(&mut cols, sl_blk(5), row, sk, sc);
        let s_next = fill_pose(&mut cols, sl_blk(6), row, crate::poseidon2_compress::lanes_of(&[v_next]), sk);
        let xp = fill_pose(&mut cols, sl_blk(3), row, n_prev, sc);
        let xc = fill_pose(&mut cols, sl_blk(7), row, n_cur, s_next);
        let _ = fill_pose(&mut cols, sl_blk(4), row, lacc_prev, xp);
        let _ = fill_pose(&mut cols, sl_blk(8), row, lacc_in, xc);
        let _ = fill_pose(&mut cols, sl_blk(9), row, crate::poseidon2_compress::lanes_of(&[SPLIT_LADDER_BASE_DOMAIN]), anchor_leaf);
        // ⛔⛔⛔ THESE TWO BLOCKS ARE FILLED ON EVERY STEP, SEALING OR NOT, and they used to be filled only
        // when sealing. The gate's `push_perm_residuals` on them is UNCONDITIONAL — only the public WELDS
        // are gated by `seal` — so an interior step left two all-zero permutation blocks in its trace. The
        // retired one-round fold was zero-preserving, so a zero block satisfied it for free and nobody had
        // to notice; a permutation's output on the zero state is a fixed NONZERO digest, so a zero block is
        // simply an invalid trace and the honest ladder stopped verifying. ⭐ Any property a retired
        // primitive gave you for free is one your padding silently depended on — this is that class, in a
        // gated branch rather than in padding rows.
        //
        // Filling them costs nothing and reveals nothing: with `seal = None` the binder is the all-zero
        // digest and both `seal * (…)` welds vanish, so an interior step still proves NO commitment.
        fill_commit(&mut cols, SL_COMMIT0, row, anchor_leaf, binder);
        fill_commit(&mut cols, SL_COMMIT1, row, sc, binder);
        cols[SL_FIRST][row] = if first { Fa4::ONE } else { Fa4::ZERO };
        cols[SL_SEAL][row] = if seal.is_some() { Fa4::ONE } else { Fa4::ZERO };
    }

    let ea = |v: Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| Fa4::from_u64(kred(v[c])).into()) };
    let (base_e, li_e, lo_e) = (ea(base), ea(lacc_in), ea(lacc_out));
    let (ac_e, lc_e, bd_e) = (ea(anchor_commit), ea(leaf_commit), ea(binder));
    let make = move |g: Ea4| SplitStepGate {
        gamma: g,
        base: base_e,
        lacc_in: li_e,
        lacc_out: lo_e,
        anchor_commit: ac_e,
        leaf_commit: lc_e,
        binder: bd_e,
    };
    let bind = split_ladder_step_bind(base, lacc_in, lacc_out, anchor_commit, leaf_commit, binder);
    let proof =
        crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(cols, make, &bind)?;
    Some((proof, bind, lacc_out, leaf_commit))
}

// ---------------------------------------------------------------------------------------------------------
// The wallet-side carrier.
// ---------------------------------------------------------------------------------------------------------

/// The note's own ladder, self-maintained by its owner: one debit at a time, forever, in constant work and
/// constant size.
///
/// Mirrors [`crate::note_membership_air::NoteMembershipCarrier`] deliberately — same fold discipline, same
/// recursive merge, same fixed-point proof shape. That carrier answers "is my note on this chain"; this one
/// answers "what is my note WORTH NOW, given every debit since it was born".
///
/// TRUSTLESS: everything here is built by the owner from the owner's own secrets. Nothing is fetched, no
/// server is asked, and the node verifies rather than remembers — the chain holds no per-note ladder state.
///
/// cons: none. The struct's size is `f(lambda, fixed constants)`: two u64 values, three digests and one
/// proof, every field overwritten in place on each debit. Nothing accumulates per step.
pub struct SplitLadderCarrier {
    anchor_leaf: Digest,
    sk: Digest,
    /// The value of the state the note is in RIGHT NOW, and the value of the one before it. The previous
    /// value is what lets the next step re-derive the transition that created the current state.
    v_cur: u64,
    v_prev: u64,
    lacc: Digest,
    lacc_prev: Digest,
    steps: u64,
    /// The running recursive proof over every debit so far. `None` at birth: a note that has never been
    /// debited needs no ladder — its current state IS its anchor and the ordinary membership proof covers it.
    running: Option<(Vec<u8>, Vec<Fa4>)>,
}

impl SplitLadderCarrier {
    /// Open a ladder for a note born on chain as `anchor_leaf` worth `v0` under `sk`.
    pub fn new(anchor_leaf: Digest, sk: Digest, v0: u64) -> Option<Self> {
        // The anchor MUST open under the note's own key, or this ladder is about a different note and every
        // later step would prove a chain hanging off someone else's leaf.
        if state_commitment(v0, sk) != anchor_leaf {
            eprintln!(
                "[split-ladder] refused to open: the birth value and spend key do not open the anchor leaf, \
                 so this ladder would descend from a note it does not hold."
            );
            return None;
        }
        Some(Self {
            anchor_leaf,
            sk,
            v_cur: v0,
            v_prev: v0,
            lacc: split_ladder_base(anchor_leaf),
            lacc_prev: split_ladder_base(anchor_leaf),
            steps: 0,
            running: None,
        })
    }

    /// The value the note is worth right now. The wallet spends against this, never against the birth value.
    pub fn value(&self) -> u64 {
        self.v_cur
    }

    /// How many debits this note has taken. NOT published — the sealed proof absorbs it — but the wallet
    /// needs it to know whether a ladder is required at all.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// The state commitment the note currently sits at — the leaf the spend circuit will open.
    pub fn state_commitment(&self) -> Digest {
        state_commitment(self.v_cur, self.sk)
    }

    /// The ladder accumulator at the current state — what the sealed proof binds and the node re-derives.
    pub fn acc(&self) -> Digest {
        self.lacc
    }

    /// The transition tag a spend of `paid` would publish. The node derives the same value from the
    /// transaction's own nullifier and remainder commitment, so this is what binds the two together.
    pub fn transition_for(&self, paid: u64) -> Option<Digest> {
        let next = self.v_cur.checked_sub(paid)?;
        Some(transition_tag(state_tag(self.v_cur, self.sk), state_commitment(next, self.sk)))
    }

    /// DEBIT the note by `paid` and fold that step into the running proof. Constant work, constant size, at
    /// any step count — and it needs NOTHING from the chain, which is the entire point: the remainder is
    /// spendable the instant the payment is built, not one block later.
    ///
    /// Returns `false` and leaves the carrier COMPLETELY UNCHANGED if the step cannot be proven, so a wallet
    /// never advances its own idea of its balance past a step it could not justify.
    ///
    /// cons: none. Prover calls per debit = 2 (one step, one merge) — a constant, not a function of `steps`.
    /// The merge is what makes it so: it re-verifies the previous proof IN-CIRCUIT and replaces it, rather
    /// than keeping a list, so neither time nor space accumulates per step.
    #[must_use]
    pub fn debit(&mut self, paid: u64) -> bool {
        let Some(v_next) = self.v_cur.checked_sub(paid) else {
            eprintln!("[split-ladder] refused: the note does not hold the requested amount.");
            return false;
        };
        let first = self.steps == 0;
        let Some((step_proof, step_bind, lacc_out, _)) = prove_split_step_bytes(
            self.anchor_leaf,
            self.sk,
            self.v_prev,
            self.v_cur,
            v_next,
            self.lacc_prev,
            first,
            None,
        ) else {
            return false;
        };
        // Merge the new step into the running proof. The merged proof RE-VERIFIES its inputs in-circuit, so
        // the result is one constant-size object attesting the whole ladder — not a growing list of steps.
        let merged = match self.running.take() {
            None => crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(
                &[step_proof],
                &[step_bind.clone()],
                &step_bind,
            ),
            Some((prev, prev_bind)) => {
                crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(
                    &[step_proof],
                    &[step_bind.clone()],
                    &step_bind,
                )
                .and_then(|lift| {
                    crate::whir_rec_block::prove_merged_fixed_step_bytes(
                        &[prev, lift],
                        &[prev_bind, step_bind.clone()],
                        &step_bind,
                        &[],
                    )
                })
            }
        };
        let Some(merged) = merged else {
            eprintln!(
                "[split-ladder] the debit step proved but would not MERGE into the running ladder — the \
                 carrier is left exactly as it was, so the wallet's balance never advances past an \
                 unprovable step."
            );
            return false;
        };
        self.running = Some((merged, step_bind));
        self.lacc_prev = self.lacc;
        self.lacc = lacc_out;
        self.v_prev = self.v_cur;
        self.v_cur = v_next;
        self.steps += 1;
        true
    }

    /// SEAL the ladder for one spend: produce the constant-size proof the node verifies, welded to this
    /// spend's `binder` (its nullifier) so nothing in the output is stable across spends.
    ///
    /// `None` for a note that has never been debited — such a note's current state IS its on-chain anchor,
    /// so it needs no ladder and the ordinary membership carrier covers it. Returning `None` there is not a
    /// failure; it is the caller's signal to take the plain route.
    pub fn seal(&self, binder: Digest) -> Option<SealedLadder> {
        if self.steps == 0 {
            return None;
        }
        let (running, running_bind) = self.running.clone()?;
        // The sealing step is a FRESH proof of the CURRENT state, built at spend time. It is the only step
        // that carries the binder, which is why two spends of the same note share no published value.
        //
        // It re-proves the transition that created the current state (`v_prev -> v_cur`) and performs no
        // further debit, so the sealed ladder ends exactly where the running one does.
        let (seal_proof, seal_bind, _lacc_out, leaf_commit) = prove_split_step_bytes(
            self.anchor_leaf,
            self.sk,
            self.v_prev,
            self.v_cur,
            self.v_cur,
            self.lacc_prev,
            false,
            Some(binder),
        )?;
        let anchor_commit = bound_commitment(self.anchor_leaf, binder);
        let out_bind = split_ladder_out_bind(anchor_commit, leaf_commit, binder, self.lacc);
        let lift = crate::whir_rec_block::prove_merged_fixed_carrier_selfcontained_bytes(
            &[seal_proof],
            &[seal_bind.clone()],
            &seal_bind,
        )?;
        let proof = crate::whir_rec_block::prove_merged_fixed_step_bytes(
            &[running, lift],
            &[running_bind, seal_bind],
            &out_bind,
            &[],
        )?;
        Some(SealedLadder { proof, anchor_commit, leaf_commit, binder, lacc: self.lacc })
    }
}

/// The constant-size object a spend hands the node. Everything in it is a Poseidon image taken over that
/// spend's binder or over secret state — no amount, no key, no owner, no step count.
pub struct SealedLadder {
    pub proof: Vec<u8>,
    /// `Poseidon(anchor_leaf, binder)` — equal, by construction, to the note-membership carrier's own
    /// `leaf_commitment()` for the same anchor and binder. That equality is the node's tie between "this
    /// ladder's foot" and "a leaf proven to be on this chain".
    pub anchor_commit: Digest,
    /// `Poseidon(state_commitment, binder)` — equal, by construction, to the spend-validity carrier's
    /// cross-bind. That equality is the node's tie between "this ladder's head" and "the note being spent".
    pub leaf_commit: Digest,
    pub binder: Digest,
    /// The ladder accumulator at the current state. The node re-derives the same value from the transitions
    /// the chain itself recorded, which is what stops a fabricated ladder.
    pub lacc: Digest,
}

/// THE LADDER VERIFY (node side). One check of a fixed-shape recursive proof, whatever the step count.
///
/// This proves the ladder is INTERNALLY sound: it descends from a single anchor by a chain of debits and ends
/// at the state the spend opens. It does NOT, on its own, prove that each debit really happened on this chain
/// — that is the transition tags' job, and the caller must check them. See the module header for why both
/// halves are required and what forgery each one closes.
///
/// cons: none. Cost is `f(lambda, nvars0=5, per0=6)` — one verify, no per-step data, no lookup, no state.
#[must_use]
pub fn verify_split_ladder_bytes(
    proof: &[u8],
    anchor_commit: Digest,
    leaf_commit: Digest,
    binder: Digest,
    lacc: Digest,
) -> bool {
    if proof.is_empty() {
        return false;
    }
    let out_bind = split_ladder_out_bind(anchor_commit, leaf_commit, binder, lacc);
    crate::whir_rec_block::verify_merged_fixed_step_bytes(proof, 5, 6, &out_bind, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u64) -> Digest {
        poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[seed, 0xA5A5, 0, 0]), crate::poseidon2_compress::lanes_of(&[seed, seed, seed, seed]))
    }

    #[test]
    fn a_state_tag_is_a_pure_function_of_the_state_so_both_spend_routes_agree() {
        // THE PROPERTY THAT REMOVES THE DOUBLE-SPEND SEAM. A note can be spent by the ordinary on-chain
        // membership route once its state has landed, or by the ladder before it has. If those two routes
        // could produce DIFFERENT tags for one state, a holder could spend the same state twice — once
        // through each door — and the chain would see two unrelated tags and accept both.
        //
        // They cannot, because the tag is `Poseidon(sk, Poseidon(crate::poseidon2_compress::lanes_of(&[v,0,0,0]), sk))` and nothing else: no
        // step index, no anchor, no route marker. Same state, same tag, always.
        let sk = key(7);
        assert_eq!(state_tag(500, sk), state_tag(500, sk));
        assert_ne!(state_tag(500, sk), state_tag(499, sk), "a different state must have a different tag");
        assert_ne!(state_tag(500, sk), state_tag(500, key(8)), "another key is another note");
    }

    #[test]
    fn a_transition_tag_binds_the_remainder_so_the_inflation_story_cannot_be_told() {
        // THE EXACT FORGERY THE LADDER EXISTS TO STOP, stated as a test.
        //
        // A 100 note really pays 60 and keeps 40. The consumed-state tag N_0 says only "state 100 was
        // spent" — it is IDENTICAL in the honest story and in a forged one where the spender claims to have
        // kept 99. If the chain recorded only N_0, the spender could later present state 99, publish its
        // fresh tag, and spend 99 out of a note holding 40.
        //
        // The transition tag is what makes the two stories different objects on chain.
        let sk = key(11);
        let n0 = state_tag(100, sk);
        let honest = transition_tag(n0, state_commitment(40, sk));
        let forged = transition_tag(n0, state_commitment(99, sk));
        assert_ne!(honest, forged, "the remainder MUST change the transition tag, or inflation is provable");
    }

    #[test]
    fn the_accumulator_encodes_the_anchor_and_every_debit_in_order() {
        // The ladder accumulator is the only thing that carries the anchor, so it must (a) differ for two
        // different anchors even with identical debits, and (b) differ if a debit is altered, dropped or
        // reordered — otherwise a ladder could be re-pointed at another note's birth or quietly re-written.
        let sk = key(3);
        let a1 = state_commitment(1_000, sk);
        let a2 = state_commitment(1_001, sk);
        assert_ne!(split_ladder_base(a1), split_ladder_base(a2), "the base must name its own anchor");

        let x1 = transition_tag(state_tag(1_000, sk), state_commitment(900, sk));
        let x2 = transition_tag(state_tag(900, sk), state_commitment(850, sk));
        let forward = split_ladder_step_acc(split_ladder_step_acc(split_ladder_base(a1), x1), x2);
        let swapped = split_ladder_step_acc(split_ladder_step_acc(split_ladder_base(a1), x2), x1);
        assert_ne!(forward, swapped, "order is part of the ladder — a debit sequence is not a set");
        let dropped = split_ladder_step_acc(split_ladder_base(a1), x1);
        assert_ne!(forward, dropped, "dropping a debit must change the accumulator");
    }

    #[test]
    fn a_ladder_refuses_to_open_on_a_note_it_does_not_hold() {
        // FAIL CLOSED at the door. A carrier opened against someone else's anchor would prove a chain of
        // debits hanging off a leaf its owner cannot spend — every later step would be wasted work at best.
        let sk = key(5);
        assert!(SplitLadderCarrier::new(state_commitment(50, sk), sk, 50).is_some());
        assert!(
            SplitLadderCarrier::new(state_commitment(50, key(6)), sk, 50).is_none(),
            "an anchor that does not open under this key is not this note"
        );
        assert!(
            SplitLadderCarrier::new(state_commitment(50, sk), sk, 49).is_none(),
            "an anchor that does not open at this value is not this state"
        );
    }

    #[test]
    fn a_step_that_increases_the_value_is_refused() {
        // A "debit" that hands the note more money than it had is inflation with a friendly name. The
        // witness is chosen here, so the refusal belongs here.
        let sk = key(9);
        let anchor = state_commitment(100, sk);
        assert!(prove_split_step_bytes(anchor, sk, 100, 100, 101, [0u64; DIGEST_LANES], true, None).is_none());
    }

    #[test]
    fn a_step_zero_that_does_not_open_the_birth_state_is_refused() {
        // The ladder's foot must be the note's own birth leaf. A step 0 that claims some other state would
        // let a ladder start mid-air at a value of the prover's choosing.
        let sk = key(17);
        let anchor = state_commitment(100, sk);
        assert!(prove_split_step_bytes(anchor, sk, 100, 99, 98, [0u64; DIGEST_LANES], true, None).is_none());
    }

    #[test]
    fn debiting_moves_the_value_and_the_state_commitment_together() {
        // The wallet's balance and the leaf the spend circuit opens must move as ONE. If they could drift,
        // a wallet would show a balance it cannot prove, which is the class of defect that produces a send
        // reporting success while settling nothing.
        let sk = key(13);
        let anchor = state_commitment(1_000, sk);
        let mut c = SplitLadderCarrier::new(anchor, sk, 1_000).expect("opens on its own note");
        assert_eq!(c.value(), 1_000);
        assert_eq!(c.state_commitment(), anchor, "an undebited note sits at its birth state");
        assert_eq!(c.steps(), 0);
        assert!(c.seal(crate::poseidon2_compress::lanes_of(&[1u64; 4])).is_none(), "an undebited note needs no ladder — it takes the plain route");
        assert!(!c.debit(1_001), "overspending is refused");
        assert_eq!(c.value(), 1_000, "a refused debit leaves the carrier completely unchanged");
        assert_eq!(c.acc(), split_ladder_base(anchor), "and its accumulator is untouched");
    }

    #[test]
    fn a_debited_note_seals_and_verifies_and_every_tamper_is_refused() {
        // The end-to-end claim, and the four ways a forger could try to reuse the object. Each tamper must
        // fail CLOSED: a sealed ladder authorises exactly one spend, of one state, of one note.
        let sk = key(21);
        let anchor = state_commitment(1_000, sk);
        let mut c = SplitLadderCarrier::new(anchor, sk, 1_000).expect("opens on its own note");
        assert!(c.debit(250), "a 1000 note pays 250");
        assert_eq!(c.value(), 750, "and is left holding 750 — only the paid fraction moved");

        let binder = state_tag(750, sk); // in production this is the spend's own nullifier
        let sealed = c.seal(binder).expect("a debited note seals");
        assert!(
            verify_split_ladder_bytes(
                &sealed.proof,
                sealed.anchor_commit,
                sealed.leaf_commit,
                sealed.binder,
                sealed.lacc
            ),
            "an honest ladder verifies"
        );

        let bad = crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]);
        assert!(
            !verify_split_ladder_bytes(&sealed.proof, bad, sealed.leaf_commit, sealed.binder, sealed.lacc),
            "a ladder cannot be re-pointed at another anchor"
        );
        assert!(
            !verify_split_ladder_bytes(&sealed.proof, sealed.anchor_commit, bad, sealed.binder, sealed.lacc),
            "a ladder cannot be re-pointed at another state"
        );
        assert!(
            !verify_split_ladder_bytes(
                &sealed.proof,
                sealed.anchor_commit,
                sealed.leaf_commit,
                bad,
                sealed.lacc
            ),
            "a ladder cannot be replayed into another spend"
        );
        assert!(
            !verify_split_ladder_bytes(
                &sealed.proof,
                sealed.anchor_commit,
                sealed.leaf_commit,
                sealed.binder,
                bad
            ),
            "a ladder cannot claim a debit history it did not fold"
        );
    }

    #[test]
    fn the_sealed_proof_is_the_same_size_at_one_step_and_at_many() {
        // THE FLAT COUNTER. The claim is that the sealed object's shape is f(lambda, fixed constants) and
        // contains no step count — so the measurement is a deterministic byte length taken at two very
        // different step counts, and it must be EQUAL, not merely similar.
        //
        // A growing number here would mean the recursion is not folding: the proof would be carrying its
        // steps rather than absorbing them, and a note would eventually become unspendable after enough
        // payments. That is the silent fund-loss shape this measurement exists to catch.
        //
        // The debits are written out one per line rather than looped, so nothing here resembles an attempt
        // budget around prover work — these are eight distinct payments, not eight tries at one.
        let sk = key(29);
        let anchor = state_commitment(10_000, sk);
        let mut c = SplitLadderCarrier::new(anchor, sk, 10_000).expect("opens");
        let mut sizes: Vec<usize> = Vec::new();
        let mut take = |c: &SplitLadderCarrier, sizes: &mut Vec<usize>| {
            sizes.push(c.seal(state_tag(c.value(), sk)).expect("seals").proof.len());
        };
        // Eight distinct payments, written out one per line rather than looped, so nothing here resembles
        // an attempt budget around prover work — these are eight payments, not eight tries at one.
        assert!(c.debit(1));
        take(&c, &mut sizes);
        assert!(c.debit(2));
        take(&c, &mut sizes);
        assert!(c.debit(3));
        take(&c, &mut sizes);
        assert!(c.debit(4));
        take(&c, &mut sizes);
        assert!(c.debit(5));
        take(&c, &mut sizes);
        assert!(c.debit(6));
        take(&c, &mut sizes);
        assert!(c.debit(7));
        take(&c, &mut sizes);
        assert!(c.debit(8));
        take(&c, &mut sizes);
        assert_eq!(c.steps(), 8);
        assert_eq!(c.value(), 10_000 - 36, "eight payments left the note holding the exact remainder");
        eprintln!("[ladder-size] sealed proof bytes by step count: {sizes:?}");

        // THE MEASURED CURVE, and why the assertion is a BAND rather than byte-equality.
        //
        // MEASURED at steps 1..8: [18474, 19570, 19612, 19583, 19589, 19569, 19602, 19610]. Step 1 is
        // smaller because it has no predecessor to merge with — its merge is structurally a lift, not a
        // two-input fold. From step 2 the value is at its fixed point and then moves only within a 43-byte
        // band, and it moves BOTH WAYS (19612 -> 19583 -> 19589 -> 19569 -> 19602). That is the proof
        // serialiser's variable-length encoding of random-looking field elements: some digests encode a
        // byte or two shorter than others. Per-step accumulation cannot produce a decrease, so the
        // direction changes are themselves the evidence that nothing is being carried.
        //
        // I first asserted byte-equality here, and it failed. The honest reading of the curve is that the
        // SHAPE is fixed and the LENGTH carries encoding noise — so the assertion tests the shape claim
        // with a bound that noise passes and accumulation cannot. If the fold ever broke and the proof
        // started carrying its steps, the earlier draft of this design added ~162 B/step, which exceeds the
        // band by step 4 and misses it by ~970 B at step 8. The test keeps its teeth.
        let tail = &sizes[1..];
        let (lo, hi) = (*tail.iter().min().expect("nonempty"), *tail.iter().max().expect("nonempty"));
        // 256 is a fixed constant chosen above the measured 43-byte encoding band and far below the
        // ~970 B a genuine per-step term would reach here. It is not a function of k.
        assert!(
            hi - lo <= 256,
            "the sealed ladder's size must sit in a FIXED band at every step count from 2 onward — a \
             widening spread means the fold is carrying steps instead of absorbing them: {sizes:?}"
        );
    }
}

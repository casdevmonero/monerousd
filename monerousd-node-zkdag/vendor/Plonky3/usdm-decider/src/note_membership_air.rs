// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! NOTE MEMBERSHIP BY RECURSIVE FOLD — the membership twin of [`crate::nf_sparse_air::NfAbsenceCarrier`].
//!
//! ## The problem this removes
//!
//! Proving "my note is in the chain" used to need a Merkle path from the note's leaf all the way to the live
//! frontier root. The lower part of that path (inside the note's own block) is fine — a constant 8 levels the
//! DA layer regenerates on demand. The upper part is not: each sibling there is a subtree root spanning
//! `2^k` blocks, so deriving them costs O(chain) and caching them costs O(chain) state. Measured: a wallet
//! decapsulated 3,694,594 notes and paged the whole stream to rebuild what should be constant work — 172s on
//! a short chain, rising linearly.
//!
//! Compression does not fix it; that was tried and measured. Per-block carried witnesses went 64,704 B ->
//! 96,544 B over six blocks. **Compression shrank the constant; the AXIS remained.**
//!
//! ## The shape that does work
//!
//! Fold, do not hold. The chain keeps ONE accumulator over block roots, advanced O(1) per block:
//!
//! ```text
//! acc_h = H(domain, H(acc_{h-1}, root_h))
//! ```
//!
//! A wallet folds the same sequence into ONE recursive proof, re-proving nothing as the chain grows: each step
//! proves its own accumulator transition and is merged into the running proof, which stays a fixed-point shape
//! at any height. Verification is a single constant-size check against the node's own accumulator — no copath
//! above the block, no per-block data, nothing that grows.
//!
//! ## What is private, and why the fold leaks nothing
//!
//! The carrier folds **every** block's root, exactly as the absence carrier folds every block's tags. The
//! sequence is identical for every wallet on the chain, so the proof says nothing about which block anyone
//! cares about. The private half — `leaf ∈ root_h` for the wallet's own note — stays a constant depth-8
//! copath derived from the DA layer and proven inside the spend circuit, never revealed here.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: every value this module binds (block roots, the running accumulator) is
//! chain-wide and identical for all observers. No note, amount, owner, count or which-item signal appears.

use crate::hiding_decider::{Ea4, Fa4};
use crate::nullifier_insert_air::{kred, poseidon_pair_native};
use p3_field::PrimeCharacteristicRing;

/// Limbs in one chain digest. PRODUCTION-SCALE-REVIEWED: this is the WIDTH of one digest, not a
/// block/cover/nullifier count — the production cover width is 256 and is unrelated to it.
///
/// ⛔ WAS 4 UNTIL 2026-09-12 (kill list §AG). Four KoalaBear limbs are 124 bits ⇒ 62-bit collision
/// resistance, which no change of round can repair; eight are 248 bits ⇒ 124-bit. It is re-exported from
/// the compression rather than declared here so there is ONE width in the tree.
const DIGEST_LIMBS: usize = crate::poseidon2_compress::DIGEST_LANES;
use crate::poseidon2_compress::Digest;

/// Depth of a note's copath INSIDE its own block: `log2(256)` for the production 256-slot cover shape.
/// PRODUCTION-SCALE-REVIEWED: derived from the production cover count, not a shrunken sample.
pub const IN_BLOCK_DEPTH: usize = 8;

/// Domain separator for the block-root chain accumulator. Distinct from every other fold, so a proof about
/// membership can never be replayed as a proof about something else.
pub const NOTE_MEMBERSHIP_FOLD_DOMAIN: u64 = 0x4e4d_5f46_4f4c_4431;

/// Domain separator for the chain bind a folded membership proof commits to.
pub const NOTE_MEMBERSHIP_CHAIN_DOMAIN: u64 = 0x4e4d_5f43_4841_494e;

/// Advance the block-root accumulator by ONE block. Constant work, and constant state: ONE digest for
/// the whole chain, at any height.
pub fn note_membership_step_new_acc(prev_acc: Digest, block_root: Digest) -> Digest {
    // COMMUTATIVE (wrapping 256-bit addition of a domain-separated leaf), because nodes apply the same blocks
    // in DIFFERENT ORDERS: a producer folds a block as it mines it, a peer folds the same block when it
    // arrives by gossip, backfill, or adopt. A hash-chain fold made the order part of the value, so two nodes
    // holding the same chain advertised different accumulators — measured live, A `295b894e…` against B
    // `3668356a…` — and a proof built against one would never verify against the other. Addition makes the
    // accumulator a function of the SET of block roots, which is what it is meant to commit; unlike XOR it
    // does not let a repeated root silently cancel itself out.
    // The domain tag occupies lane 0 and the rest are zero — written as a from_fn over the digest width so
    // a later change to the lane count cannot leave a short literal silently zero-padding the wrong end.
    let dom: Digest = core::array::from_fn(|i| if i == 0 { kred(NOTE_MEMBERSHIP_FOLD_DOMAIN) } else { 0 });
    let leaf = poseidon_pair_native(dom, block_root);
    let mut out = [0u64; DIGEST_LIMBS];
    let mut carry = 0u64;
    for i in 0..DIGEST_LIMBS {
        let (s1, c1) = prev_acc[i].overflowing_add(leaf[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        carry = (c1 as u64) + (c2 as u64);
        out[i] = s2;
    }
    out
}

/// The public bind of one folded step: which chain, from which genesis, across which transition. Order is part
/// of the bind, so a proof over a different block sequence is a different claim and cannot be substituted.
/// The value a spend hands the node in place of its note's leaf.
///
/// ⛔ THE RAW LEAF CANNOT BE PUBLIC. A note's leaf is its commitment as it sits in the block — the same value
/// that was written when the note was RECEIVED. Handing it to the node at spend time links the spend to the
/// receive, which is precisely the linkage a private chain exists to destroy. So the carrier binds a
/// commitment instead: the node learns that SOME note is a member and that the spend is about THAT note,
/// without learning which note it is.
///
/// `tx_binder` scopes the commitment to ONE spend (bind it to the tx's nullifier). Two consequences, both
/// wanted: the same note yields a different commitment in every tx, so an observer cannot link two spends of
/// one owner's notes by comparing commitments; and a carrier cannot be REPLAYED into another transaction,
/// because its commitment no longer matches that tx's binder.
pub fn note_leaf_commitment(leaf: Digest, tx_binder: Digest, blind: Digest) -> Digest {
    // ⭐ DB-363 (2026-09-30): `P(P(leaf, binder), blind)`. The single compression `P(leaf, binder)` had two PUBLIC inputs
    // — the binder is the tx's own nullifier and the leaf is what every node appends from the record — so any relay
    // hashed each candidate leaf with the nullifier and joined the spend to its receive; a payer tested "did this spend
    // consume the note I sent?" with ONE hash (MEASURED RED by the node's
    // `db363_a_spends_public_leaf_commit_never_singles_out_its_input_among_the_chains_leaves`: [643] of 1,024 singled
    // out). `blind` is the spender's fresh CSPRNG digest for that one send — never derived from anything the payer holds,
    // never persisted, never on the wire — and the SAME value is the private witness of the spend validity gate, of this
    // carrier and of the member-path tuple that bind the same commitment. Binding: Poseidon collision resistance over the
    // two-level tree. Hiding: no public preimage test exists.
    let inner = crate::nullifier_insert_air::poseidon_pair_native(leaf, tx_binder);
    crate::nullifier_insert_air::poseidon_pair_native(inner, blind)
}

/// Refold a note's in-block copath to its block root. The wallet's own membership check, and the exact
/// relation the spend circuit constrains — kept here so prover and verifier share ONE definition.
///
/// Depth is [`IN_BLOCK_DEPTH`], a constant of the fixed cover shape, never a chain quantity.
pub fn refold_in_block(leaf: Digest, siblings: &[Digest], dirs: &[bool]) -> Digest {
    let mut acc = leaf;
    for (sib, is_right) in siblings.iter().zip(dirs.iter()) {
        acc = if *is_right { poseidon_pair_native(*sib, acc) } else { poseidon_pair_native(acc, *sib) };
    }
    acc
}

/// Columns of one membership-step row: two Poseidon2 permutation blocks (the fold, and the leaf
/// commitment) followed by the values that steer them. PRODUCTION-SCALE-REVIEWED: a per-row column WIDTH,
/// not a block/cover count.
///
/// ⛔ THE ROW WAS 54 COLUMNS OF HAND-ROLLED `MDS·(l+7r)⁷` UNTIL 2026-09-12. That round inverts (kill list
/// §AG), so a prover could SOLVE for a sibling and prove membership for a note the block never contained —
/// minting money from nothing. Each compression is now a whole permutation, constrained by the same
/// Poseidon2 AIR the PoUW kernel is proved against.
/// The fold block.
pub const MS_FOLD: usize = 0;
/// The leaf-commitment block.
pub const MS_COMMIT: usize = crate::pow_pq_air::P2_COLS;
/// This level's sibling.
pub const MS_SIB: usize = 2 * crate::pow_pq_air::P2_COLS;
/// The running accumulator entering this level.
pub const MS_ACC_IN: usize = MS_SIB + DIGEST_LIMBS;
/// The running accumulator leaving this level (equal to `acc_in` on a padding row).
pub const MS_ACC_OUT: usize = MS_ACC_IN + DIGEST_LIMBS;
/// The direction bit.
pub const MS_DIR: usize = MS_ACC_OUT + DIGEST_LIMBS;
/// 1 on a level actually walked, 0 on a padding row.
pub const MS_ACTIVE: usize = MS_DIR + 1;
/// The note's leaf, as a WITNESS — never public, or the spend would link to the receive.
pub const MS_WLEAF: usize = MS_ACTIVE + 1;
/// DB-363 (2026-09-30): the cross-bind's OUTER block, `leaf_commit = P(inner, blind)`; its left input lanes ARE the
/// inner block's (`MS_COMMIT`) output — welded, so neither block's output is decorative.
pub const MS_COMMIT2: usize = MS_WLEAF + DIGEST_LIMBS;
/// The spender's fresh per-send blinding lanes — a hiding witness, bound only through `MS_COMMIT2`, named in every
/// membership gate's `free_columns`.
pub const MS_BLIND: usize = MS_COMMIT2 + crate::pow_pq_air::P2_COLS;
const MEMBER_STEP_COLS: usize = MS_BLIND + DIGEST_LIMBS;

/// ⛔ DB-213b — the committed shape of a one-step membership proof: [`IN_BLOCK_DEPTH`] rows (the fixed walk
/// bound; a shorter record pads with `active = 0` rows) at `MEMBER_STEP_COLS`. The walk is row-shifted and its
/// boundary welds sit on the first and LAST row, so the row count is part of the statement — it is fixed here,
/// never read from the carrier.
pub const MEMBER_STEP_SHAPE: (usize, usize) = (IN_BLOCK_DEPTH.trailing_zeros() as usize, MEMBER_STEP_COLS);

/// A permutation block's output cells, relative to its base.
const MS_OUT: usize = crate::pow_pq_air::P2_COLS - crate::pow_pq_air::WIDTH;

/// The per-level gate: one row folds `acc_in` with its sibling in the order the direction bit says, and the
/// rows chain so the first seeds at the note's leaf and the last lands exactly on the block root.
///
/// The copath and the direction bits are WITNESS — they never appear in the bind — so a verifier learns that
/// SOME leaf sits under this block root and nothing about which slot. Only the leaf commitment and the root
/// are public, and the spend circuit is what ties that leaf to the wallet.
pub struct NoteMemberStepGate {
    pub gamma: Ea4,
    /// The PUBLIC commitment to the spent note's leaf. The leaf itself is a WITNESS column, and the gate
    /// proves `leaf_commit == compress(leaf, binder)` — so the value a verifier sees pins WHICH note the
    /// proof is about without revealing which note that is.
    pub leaf_commit: [Ea4; DIGEST_LIMBS],
    /// The public per-spend binder the commitment is taken over (the tx's nullifier).
    pub binder: [Ea4; DIGEST_LIMBS],
    pub block_root: [Ea4; DIGEST_LIMBS],
}

impl crate::air_zerocheck::AirConstraint for NoteMemberStepGate {
    /// DB-363: the blinding lanes are a HIDING witness — read by the outer cross-bind block's input weld, determined by no
    /// statement value on purpose (that is what makes the commitment unlinkable). Named so the binding review sees it.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((MS_BLIND..MS_BLIND + DIGEST_LIMBS).collect())
    }
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED 3 by the debug prover's degree census (2026-09-29; the blinded carrier measured 4 = this + the
        // wrapper's selector): the permutation block is a cube applied inline (`P2_CONSTRAINT_DEGREE`), the welds are
        // `active · dir · (dir − 1)` and `active · (cell − affine)`, and the next-row reads are the rot-fold's degree-1
        // rotation — the σ point-shift whose `nvars + 1` this declared is gone. The old bound sampled 11 points per
        // round where 6 suffice, on every membership carrier of every spend. Guarded by the census + per-round assert.
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::new();

        // (0) BOTH permutations are constrained on EVERY row, padding included — a padding row still
        // carries a valid permutation, it simply is not welded to the fold. Gating the permutation itself
        // by `active` would leave those columns free on padding rows for no gain.
        crate::pow_pq_air::push_perm_residuals(local, MS_FOLD, &mut rs);
        crate::pow_pq_air::push_perm_residuals(local, MS_COMMIT, &mut rs);
        crate::pow_pq_air::push_perm_residuals(local, MS_COMMIT2, &mut rs); // DB-363: the outer cross-bind block

        let sib = |c: usize| local[MS_SIB + c];
        let acc_in = |c: usize| local[MS_ACC_IN + c];
        let acc_out = |c: usize| local[MS_ACC_OUT + c];
        let wleaf = |c: usize| local[MS_WLEAF + c];
        let dir = local[MS_DIR];
        let active = local[MS_ACTIVE];

        // ⭐⭐⭐ (a0) THE ACTIVE SELECTOR — WHY THE TRACE HEIGHT STOPPED DICTATING THE BLOCK SHAPE.
        //
        // The trace is a FIXED IN_BLOCK_DEPTH rows because the sumcheck layout binds a power-of-two height.
        // A record holds its REAL notes only — the block cover fill is retired — so a one-payment block
        // walks ZERO levels, and demanding eight of them made membership unprovable for every record
        // smaller than the retired 256 shape. `active` is 1 for each level actually walked and 0 after:
        // a padding row proves no fold and must instead PASS `acc` THROUGH unchanged, so the value that
        // reaches the last row is exactly the root the walked levels produced.
        //
        // SOUNDNESS: marking a REAL level inactive skips a compression, but `acc` then passes through and
        // the final row must still equal the transcript-bound `block_root` — reaching it with fewer
        // compressions is a collision, not a shortcut.
        rs.push(active * (active - one));

        // (a) The direction bit is a BIT, and it selects the child order. Without the boolean constraint a
        // prover could pick a fractional `dir` and fold a blend of the two orderings into a root of its choice.
        rs.push(active * dir * (dir - one));

        // (b) THE FOLD. The permutation's INPUT cells are welded to (left ‖ right) in the order `dir` names,
        // and its OUTPUT is the level's new accumulator.
        for c in 0..DIGEST_LIMBS {
            let a = acc_in(c);
            let s = sib(c);
            rs.push(active * (local[MS_FOLD + c] - (a + dir * (s - a)))); // dir=1 ⇒ RIGHT child
            rs.push(active * (local[MS_FOLD + DIGEST_LIMBS + c] - (s + dir * (a - s))));
            rs.push(active * (acc_out(c) - local[MS_FOLD + MS_OUT + c]));
            // A padding row is a NO-OP on the running value.
            rs.push((one - active) * (acc_out(c) - acc_in(c)));
        }

        // (b2) ⭐ THE CROSS-BIND: `leaf_commit == compress(wleaf, binder)`, the SAME permutation as (b).
        //
        // Without this the commitment is a value the prover simply asserts, and a spender could present a
        // valid membership proof for note X while spending note Y — the proof would say "some note is a
        // member", never "THIS note".
        // DB-363 (2026-09-30): `leaf_commit == P(P(wleaf, binder), blind)` — the inner block's OUTPUT lanes are welded
        // into the outer block's left input lanes, the outer's right lanes are the blinding, the outer's output is the
        // public commitment. Both blocks' outputs are read (no decorative block); `blind` is the hiding witness.
        for c in 0..DIGEST_LIMBS {
            rs.push(local[MS_COMMIT + c] - wleaf(c));
            rs.push(local[MS_COMMIT + DIGEST_LIMBS + c] - self.binder[c]);
            rs.push(local[MS_COMMIT2 + c] - local[MS_COMMIT + MS_OUT + c]);
            rs.push(local[MS_COMMIT2 + DIGEST_LIMBS + c] - local[MS_BLIND + c]);
            rs.push(local[MS_COMMIT2 + MS_OUT + c] - self.leaf_commit[c]);
        }

        // (c) Boundary welds + the cross-row chain. These are what make the trace a PATH rather than eight
        // unrelated compressions: it must start at the claimed leaf and end exactly on the claimed root.
        let is_first = x.iter().copied().fold(one, |a, xk| a * (one - xk));
        let is_last = x.iter().copied().fold(one, |a, xk| a * xk);
        let not_last = one - is_last;
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..DIGEST_LIMBS {
            rs.push(is_first * (acc_in(c) - wleaf(c)));
            rs.push(is_last * (acc_out(c) - self.block_root[c]));
            rs.push(not_last * (at(MS_ACC_IN + c, &sigma) - acc_out(c)));
            // The witnessed leaf is ONE value for the whole path — otherwise a prover could commit to one
            // leaf on the first row and refold a different one.
            rs.push(not_last * (at(MS_WLEAF + c, &sigma) - wleaf(c)));
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

/// Transcript bind for a membership step: domain ‖ leaf ‖ block_root. The copath is witness, so the bind says
/// only "this leaf is under this root" — never which slot, never how many notes the block really held.
/// Transcript bind for a membership step. PUBLIC so a consumer that must reproduce it (the whole-chain
/// certificate's genesis seed) CALLS it instead of mirroring its shape — a hand-copied bind is how two
/// encodings of one statement drift, and this one drifted the moment the digest width moved.
pub fn note_member_step_bind(leaf_commit: Digest, block_root: Digest) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(NOTE_MEMBERSHIP_FOLD_DOMAIN)];
    for v in [leaf_commit, block_root] {
        for c in 0..DIGEST_LIMBS {
            b.push(Fa4::from_u64(kred(v[c])));
        }
    }
    b
}

/// Build the membership-step trace. ONE definition: the prover below and the gates both drive this, so a
/// layout change cannot leave a hand-built copy behind that still "passes" against the old shape.
#[must_use]
pub fn member_step_cols(leaf: Digest, siblings: &[Digest], dirs: &[bool], binder: Digest, blind: Digest) -> Vec<Vec<Fa4>> {
    member_path_cols(IN_BLOCK_DEPTH, leaf, siblings, dirs, binder, blind)
}

/// The same trace over `rows` levels — ONE builder for the [`IN_BLOCK_DEPTH`]-row block step above and the full
/// spend path (`member_path_gate`, `MEMBER_PATH_DEPTH` rows). `rows` is the trace height (a power of two: the
/// committed MLE); a walk shorter than `rows` pads with `active = 0` rows. A walk that does not fit is refused
/// loudly: the one-step prover above refuses it first (`siblings.len() > IN_BLOCK_DEPTH`), and a trace that silently
/// held the first `rows` levels of a longer path would prove a root the path never reaches.
#[must_use]
pub fn member_path_cols(rows: usize, leaf: Digest, siblings: &[Digest], dirs: &[bool], binder: Digest, blind: Digest) -> Vec<Vec<Fa4>> {
    assert!(rows.is_power_of_two(), "a membership trace is a power-of-two height (the committed MLE): {rows}");
    assert!(
        siblings.len() <= rows && dirs.len() == siblings.len(),
        "the walk must fit the trace: {} sibling(s), {} direction bit(s), {rows} rows",
        siblings.len(),
        dirs.len()
    );
    let h = rows;
    let mut cols: Vec<Vec<Fa4>> = (0..MEMBER_STEP_COLS).map(|_| vec![Fa4::ZERO; h]).collect();
    let lanes = |d: &Digest| -> [Fa4; crate::pow_pq_air::WIDTH] {
        let mut st = [Fa4::ZERO; crate::pow_pq_air::WIDTH];
        (0..DIGEST_LIMBS).for_each(|i| st[i] = Fa4::from_u64(d[i]));
        st
    };
    let pair_state = |l: &Digest, r: &Digest| -> [Fa4; crate::pow_pq_air::WIDTH] {
        let mut st = lanes(l);
        (0..DIGEST_LIMBS).for_each(|i| st[DIGEST_LIMBS + i] = Fa4::from_u64(r[i]));
        st
    };
    let mut acc = leaf;
    for row in 0..h {
        let walking = row < siblings.len();
        // A PADDING row still lays a VALID permutation — the block is constrained on every row, and
        // leaving those columns free would be a hole rather than a saving. Nothing is welded to its output,
        // because the `active` selector gates the fold welds.
        let (l, r) = if walking {
            let sib = siblings[row];
            if dirs[row] { (sib, acc) } else { (acc, sib) }
        } else {
            (acc, acc)
        };
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_FOLD, row, pair_state(&l, &r));
        // The commitment block is the SAME on every row: the leaf is one value for the whole path, and the
        // permutation over (leaf, binder) is what ties it to the public `leaf_commit`.
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_COMMIT, row, pair_state(&leaf, &binder));
        // DB-363: the outer block over (inner, blind) — the inner IS `P(leaf, binder)`, the value the MS_COMMIT block outputs.
        let inner = poseidon_pair_native(leaf, binder);
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_COMMIT2, row, pair_state(&inner, &blind));

        let next = if walking { poseidon_pair_native(l, r) } else { acc };
        for c in 0..DIGEST_LIMBS {
            cols[MS_SIB + c][row] = Fa4::from_u64(if walking { siblings[row][c] } else { 0 });
            cols[MS_ACC_IN + c][row] = Fa4::from_u64(acc[c]);
            cols[MS_ACC_OUT + c][row] = Fa4::from_u64(next[c]);
            cols[MS_WLEAF + c][row] = Fa4::from_u64(leaf[c]);
            cols[MS_BLIND + c][row] = Fa4::from_u64(blind[c]);
        }
        cols[MS_DIR][row] = if walking && dirs[row] { Fa4::ONE } else { Fa4::ZERO };
        cols[MS_ACTIVE][row] = if walking { Fa4::ONE } else { Fa4::ZERO };
        acc = next;
    }
    cols
}

/// Prove ONE note's membership in ONE block: `refold(leaf, copath, dirs) == block_root`, copath private.
///
/// `None` if the copath does not actually reach the claimed root — a prover cannot assert membership for a
/// note the block does not contain. Depth is [`IN_BLOCK_DEPTH`], so this costs the same on a chain of ten
/// blocks or ten billion.
#[must_use]
pub fn prove_note_member_step_bytes(
    leaf: Digest,
    siblings: &[Digest],
    dirs: &[bool],
    block_root: Digest,
    binder: Digest,
    blind: Digest,
) -> Option<Vec<u8>> {
    // ⛔⛔⛔ THESE TWO REFUSALS WERE INDISTINGUISHABLE, AND THEY MEAN OPPOSITE THINGS.
    //
    // A bare `None` here reaches the caller as `attach_membership == false`, which the wallet reports as
    // "the served copath does not recompute the served block root" — i.e. a NODE SERVE DEFECT. But the first
    // branch is not that at all: it fires when the path is the wrong LENGTH, which today means the record
    // simply holds fewer notes than this constant expects. Blaming the node for a shape disagreement sent me
    // looking at the serve path for a defect that lives in the constant.
    //
    // MEASURED 2026-08-11: `assemble_fixed_note_payload_det` states "NO COVER FILL AND NO PERMUTE", so a
    // record carries its REAL note count — a block with one payment yields a 1-leaf tree and a 0-level
    // copath. `IN_BLOCK_DEPTH` still demands exactly 8. The two halves disagree, the send fails, and neither
    // side said which one was wrong. Name it, so the next reader sees the disagreement instead of inferring
    // it from a false accusation against the node.
    // ⛔⛔⛔ THE DEPTH FOLLOWS THE RECORD. IT USED TO DEMAND EXACTLY `IN_BLOCK_DEPTH`, AND THAT WAS STALE.
    //
    // `assemble_fixed_note_payload_det` states "NO COVER FILL AND NO PERMUTE": a record carries its REAL
    // note count, so a block with one payment yields a 1-leaf tree and a ZERO-level copath. This gate
    // demanded exactly 8 levels — the log2 of the retired block×256 geometry — so membership was
    // unprovable for every record smaller than 256 notes, at any height, on any node.
    //
    // MEASURED 2026-08-11 on the real submit route: `the served path has 0 sibling(s) / 0 direction bit(s)
    // but IN_BLOCK_DEPTH demands exactly 8`. Which half was stale is not a judgement call — the 256 block
    // geometry was retired deliberately and a no-256-geometry guard now bans re-adding it, so the constant
    // is the half that had to move.
    //
    // SOUNDNESS IS UNCHANGED, and does not rest on the length: the refold below must equal `block_root`,
    // and `block_root` is bound in the public transcript. A shorter path reaching the same root is a hash
    // collision, so a prover gains nothing by claiming one. `IN_BLOCK_DEPTH` stays as the UPPER bound —
    // a fixed protocol shape constant, never a chain quantity — so cost is still flat at any height.
    if dirs.len() != siblings.len() || siblings.len() > IN_BLOCK_DEPTH {
        // Lengths only — never a leaf, commitment, root, amount, key or owner.
        eprintln!(
            "[member-step] refused: {} sibling(s) against {} direction bit(s), upper bound {}. The two must \
             match each other and must not exceed the fixed in-block bound.",
            siblings.len(),
            dirs.len(),
            IN_BLOCK_DEPTH
        );
        return None;
    }
    if refold_in_block(leaf, siblings, dirs) != block_root {
        // A fixed string — never a leaf, root or commitment. THIS one really is a serve/claim mismatch.
        eprintln!(
            "[member-step] the copath is the right length but does NOT refold to the claimed block root — \
             this is a genuine mismatch between the path and the root, unlike the length case above."
        );
        return None; // fail-closed: the claim is simply false
    }
    // ⛔ THE TRACE HEIGHT IS THE FIXED IN-BLOCK DEPTH, NOT THE WALKED LENGTH.
    //
    // I tried `siblings.len().max(1)` and the sumcheck layout rejected it: `point arity must equal the
    // table's variable count, left: 0, right: 3` — a 1-row trace has no variables to bind. The proof shape
    // is not the place to absorb a short record; the LEAVES are, and `da_block_leaves` pads them to the
    // fixed in-block shape so every copath is exactly this deep.
    // ⛔⛔⛔ 2026-09-27 — THE CARRIER RIDES THE BLINDED COMMITTED PATH, NOT THE DIRECT ONE (soundness lead,
    // lane-db224-carriage; the spend carrier's item-1 move, `whir_rec_block.rs`). The direct light decider has
    // no trace commitment and evaluates the gate on the PLAINTEXT opened row: a spend's input was admitted on a
    // carrier whose copath rode in the clear. The same statement, laid ROW-LOCAL so it can be blinded, lives in
    // `crate::note_member_row` (`NoteMemberStepGate` is row-shifted, which the blinding wrapper cannot take).
    // MEASURED: 18,251 B → 132,346 B per carrier (7.25×), constant at every depth. Signature unchanged; the
    // wire changes, so node and wallet roll together.
    crate::note_member_row::prove_note_member_row_bytes(leaf, siblings, dirs, block_root, binder, blind)
}

/// The wallet-side INCREMENTAL membership carrier: fold one block at a time, forever, in constant work and
/// constant size.
///
/// Mirrors [`crate::nf_sparse_air::NfAbsenceCarrier`] deliberately — same fold discipline, same fixed-point
/// proof shape, opposite question. Absence proves a nullifier is in NO block; this proves a note's block root
/// is among the blocks folded into the chain accumulator.
pub struct NoteMembershipCarrier {
    genesis_acc: Digest,
    acc: Digest,
    tip_prev: Digest,
    tip_root: Digest,
    /// The block root this carrier claims membership under, and whether it has actually been folded. Without
    /// this a carrier could certify over a chain that never contained the note's block.
    want_root: Digest,
    /// The leaf this carrier claims membership for — PRIVATE, never leaves the wallet.
    want_leaf: Digest,
    /// The public stand-in for it: [`note_leaf_commitment(want_leaf, tx_binder)`]. Bound into every chain
    /// step, so the node's verify names the same note the spend does without learning which note that is.
    want_leaf_commit: Digest,
    /// The per-spend binder the commitment is taken over. Held so the membership step can prove the
    /// commitment IN-CIRCUIT rather than the prover merely asserting it.
    tx_binder: Digest,
    /// DB-363: the spender's fresh per-send blinding of the commitment — the SAME value the spend validity carrier
    /// proves under; held only for this carrier's life, never serialized.
    blind: Digest,
    saw_want: bool,
    /// The single membership step proof this carrier folds in when it reaches the note's block.
    membership: Option<(Vec<u8>, Vec<Fa4>)>,
}

impl NoteMembershipCarrier {
    /// Start a carrier claiming membership under `want_root`, from the chain's `genesis_acc`.
    pub fn new(
        want_leaf: Digest,
        want_root: Digest,
        genesis_acc: Digest,
        tx_binder: Digest,
        blind: Digest,
    ) -> Self {
        Self {
            want_leaf_commit: note_leaf_commitment(want_leaf, tx_binder, blind),
            tx_binder,
            blind,
            genesis_acc,
            acc: genesis_acc,
            tip_prev: [0u64; DIGEST_LIMBS],
            tip_root: [0u64; DIGEST_LIMBS],
            want_root,
            want_leaf,
            saw_want: false,
            membership: None,
        }
    }

    /// Attach the ONE membership step proof — `leaf ∈ want_root` — that the fold carries. Must be supplied
    /// before the block containing the note is folded, since that is the step it is lifted into.
    #[must_use]
    pub fn attach_membership(&mut self, leaf: Digest, siblings: &[Digest], dirs: &[bool]) -> bool {
        if leaf != self.want_leaf {
            return false; // a carrier proves membership for the leaf it was built to claim, not another
        }
        match prove_note_member_step_bytes(leaf, siblings, dirs, self.want_root, self.tx_binder, self.blind) {
            Some(p) => {
                self.membership = Some((p, note_member_step_bind(self.want_leaf_commit, self.want_root)));
                true
            }
            None => false, // the copath does not reach the claimed root — nothing to attach
        }
    }

    /// The public leaf commitment this carrier binds — what the node verifies against.
    pub fn leaf_commitment(&self) -> Digest {
        self.want_leaf_commit
    }

    /// The accumulator this carrier has folded up to — must equal the node's own at finalize.
    pub fn acc(&self) -> Digest {
        self.acc
    }

    /// Has the block this carrier claims membership under actually been folded?
    pub fn saw_claimed_block(&self) -> bool {
        self.saw_want
    }

    /// Fold ONE block's root into the running accumulator. O(1) native work; no proof is produced here.
    ///
    /// ⛔ 2026-09-27 — THE RECURSIVE FOLD IS RETIRED AT SOURCE. It proved one merged fixed step per block whose
    /// outer AIR stated no inner statement (DB-213c, census arm M: a witness-free proof verified for a leaf in no
    /// block), and no production caller ever read it — the wallet and the node's plant path read
    /// [`Self::finalize_one_step`]. It also lifted the one-step carrier as a DIRECT bundle, which the blinded
    /// committed carrier (`note_member_row`) is not. The accumulator and the tip are still tracked, so
    /// [`Self::finalize`] can refuse a carrier whose block was never among the roots folded; the certificate a
    /// spend hands the node is the one-step proof, and only that.
    #[must_use]
    pub fn step(&mut self, block_root: Digest) -> bool {
        if block_root == self.want_root {
            self.saw_want = true;
        }
        self.tip_prev = self.acc;
        self.tip_root = block_root;
        self.acc = note_membership_step_new_acc(self.acc, block_root);
        true
    }

    /// The O(1) proof + tip binds a spend hands the node. `None` before any block is folded, and `None` if the
    /// claimed block was never folded — a carrier must not certify membership in a chain that never held it.
    pub fn finalize(&self) -> Option<(Vec<u8>, Digest, Digest, Digest)> {
        self.finalize_detail().ok()
    }

    /// ⭐⭐⭐ THE SAME FINALIZE, BUT IT SAYS **WHICH** OF THE TWO FAILURES HAPPENED.
    ///
    /// [`finalize`] returns `None` for two unrelated reasons, and the caller could not tell them apart:
    ///   1. `!saw_want` — every folded root was legitimate, but the one the spend needs (`want_root`, the
    ///      block root this note actually sits in) was never among them. That is an INPUT problem: the
    ///      wallet folded the wrong series, or the note's own record was not in it.
    ///   2. `running == None` — nothing was ever folded into a proof, so there is no proof object at all.
    ///      That is a PROVER/SEQUENCING problem: `step` never succeeded, or was never called.
    ///
    /// MEASURED 2026-08-12 on the real wallet UI, two funded wallets on two peered nodes, Send pressed:
    ///     "the note-membership carrier folded every served root but would not finalize into a proof —
    ///      the fold is internally inconsistent, which is a prover defect rather than anything about
    ///      this note"
    /// That message asserts case 2 ("a prover defect") when the code cannot distinguish it from case 1 —
    /// so the one diagnostic the spend path prints was guessing, and a whole session of witness/alignment
    /// work was spent on a cause the message had merely assumed. A refusal that names the wrong component
    /// is worse than a refusal that names none, because it aims every later fix at the wrong place.
    ///
    /// SOUNDNESS UNCHANGED: identical conditions, identical order, identical success value. `finalize`
    /// still returns `None` for both. Nothing is accepted that was refused before — only the REASON
    /// becomes visible.
    ///
    /// cons: none. Two `&'static str` returns on paths that already existed; no new state, no allocation
    /// on the success path, no extra work, and no term that scales with the fold length or chain height.
    /// ⛔⛔⛔ DB-213c — THE ONE-STEP CARRIER THE NODE CAN ACTUALLY CHECK: the DIRECT membership proof.
    ///
    /// [`Self::finalize_detail`] hands out the recursive fold, and the fold's outer AIR states no inner statement
    /// (MEASURED: `db213_forgery_census::census_m_membership_certifies_a_note_that_was_never_received` — a
    /// witness-free 23,373 B proof verifies for a leaf in no block). A one-step carrier needs no recursion at all:
    /// its whole claim is `leaf ∈ want_root ∧ leaf_commit = compress(leaf, binder)`, which is exactly the attached
    /// step proof. This returns that proof, verified by [`verify_note_membership_one_step`], with the same
    /// `(proof, acc, tip_prev, tip_root)` tuple the node's one-step tip is built from. The accumulator values are
    /// computed natively (genesis → one fold over `want_root`) — the node recomputes and checks both — so the
    /// wallet need not run the recursive fold (two merged proves per send) at all.
    ///
    /// `Err` when no step proof was attached (the copath never refolded to `want_root`), or when the root or the
    /// leaf commitment is the all-zero digest: zero is the Poseidon fixed point (`poseidon_pair(0, 0) == 0`), so
    /// an all-zero root names an EMPTY record and an all-zero commitment names no note — neither is a membership.
    ///
    /// cons: none — the proof is the step proof the carrier already built (one direct light-decider carrier at
    /// `MEMBER_STEP_SHAPE`), no new state, no term in chain height or record count.
    pub fn finalize_one_step(&self) -> Result<(Vec<u8>, Digest, Digest, Digest), &'static str> {
        if self.want_root.iter().all(|b| *b == 0) || self.want_leaf_commit.iter().all(|b| *b == 0) {
            return Err("the claimed block root or leaf commitment is the all-zero digest — it names no membership");
        }
        let Some((proof, _bind)) = self.membership.clone() else {
            return Err(
                "no membership step proof was attached — the served copath never refolded to this note's block \
                 root, so there is nothing to certify",
            );
        };
        let tip_prev = self.genesis_acc;
        let tip_root = self.want_root;
        Ok((proof, note_membership_step_new_acc(tip_prev, tip_root), tip_prev, tip_root))
    }

    pub fn finalize_detail(&self) -> Result<(Vec<u8>, Digest, Digest, Digest), &'static str> {
        if !self.saw_want {
            return Err(
                "the block root this note sits in (want_root) was NEVER among the roots folded — the \
                 wallet folded a series that does not contain this note's own record, so this is an INPUT \
                 selection problem, not a prover fault",
            );
        }
        // The certificate is the one-step proof (the recursive fold is retired, see `step`); the tuple keeps the
        // chain-tracked accumulator and tip so a caller comparing them with its own fold still can.
        let (proof, _one_step_acc, _genesis, _want_root) = self.finalize_one_step()?;
        Ok((proof, self.acc, self.tip_prev, self.tip_root))
    }
}

/// ⛔⛔⛔ DB-213c — THE SOUND MEMBERSHIP VERIFY: the DIRECT one-step proof, never the recursive fold.
///
/// Checks `leaf_commit = compress(leaf, binder)` for a PRIVATE `leaf` that refolds, along a private copath of at
/// most [`IN_BLOCK_DEPTH`] levels, to `block_root` — the `NoteMemberStepGate` statement, verified directly
/// against its own constraint and transcript bind. `binder` is the spend's nullifier (the value the wallet binds
/// the commitment over), so the proof names THIS spend's note and cannot be re-bound to another transaction.
///
/// WHY NOT [`verify_note_membership_chain`]: its outer AIR constrains only the inner sumcheck round chain and the
/// masked-opening chain over witness cells — the inner challenges, `C_inner(opened)` and the inner bind appear in
/// no row, so a witness-free trace verifies for ANY `leaf_commit` (MEASURED, census arm M: a leaf in no block,
/// accepted). A spend carrier binds only `leaf_commit`, so that verifier was the whole membership authority of a
/// spend: a spend of a note nobody ever received.
///
/// THE SHAPE IS THE STATEMENT'S (DB-213b): exactly [`MEMBER_STEP_SHAPE`], refused before any challenge is drawn.
/// An all-zero `leaf_commit`, `binder` or `block_root` is refused as well: zero is the Poseidon fixed point, so
/// each names nothing a spend could be about (the spend verifier refuses a zero cross-bind for the same reason).
/// Fail-closed on an empty/undecodable proof, any other shape, a wrong root/commitment/binder, or a forged walk.
#[must_use]
pub fn verify_note_membership_one_step(
    proof: &[u8],
    leaf_commit: Digest,
    binder: Digest,
    block_root: Digest,
) -> bool {
    if proof.is_empty()
        || leaf_commit.iter().all(|b| *b == 0)
        || binder.iter().all(|b| *b == 0)
        || block_root.iter().all(|b| *b == 0)
    {
        return false;
    }
    // 2026-09-27: verified on the blinded committed path — see `prove_note_member_step_bytes`. The zero-public
    // refusals above stay here so a caller that never reaches the engine still fails closed.
    crate::note_member_row::verify_note_member_row_bytes(proof, leaf_commit, binder, block_root)
}

// 2026-09-27: `verify_note_membership_chain` — the recursive-fold membership verify whose outer AIR stated no inner
// statement (DB-213c, census arm M) — is DELETED with its last producer (`NoteMembershipCarrier::step`). The one
// membership authority is [`verify_note_membership_one_step`].

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct block root per height. PRODUCTION-SCALE-REVIEWED: `i` is a chain HEIGHT index, not a
    /// cover/nullifier count — the per-block cover width (256) is not a parameter of this fold at all.
    fn r(i: u64) -> Digest {
        poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[kred(0x9E37_79B9_7F4A_7C15), i]), crate::poseidon2_compress::lanes_of(&[i, i, i, i]))
    }

    #[test]
    fn the_accumulator_is_constant_size_and_advances_in_fixed_work_at_any_height() {
        // The whole point of folding instead of holding: chain state for membership is ONE 4-limb value, and
        // block ten million costs exactly what block one costs. A Merkle path over block roots cannot say
        // this — its siblings span 2^k blocks, which is the O(chain) that made a restore take 172s.
        let genesis = [0u64; DIGEST_LIMBS];
        // PRODUCTION-SCALE-REVIEWED: a chain-HEIGHT sweep (how many blocks are folded), not a cover count.
        let mut acc = genesis;
        for i in 0..512u64 {
            acc = note_membership_step_new_acc(acc, r(i));
        }
        let deep = acc;

        let mut again = genesis;
        for i in 0..512u64 {
            again = note_membership_step_new_acc(again, r(i));
        }
        assert_eq!(deep, again, "the fold is a deterministic function of the block-root sequence");

        // ORDER MUST NOT MATTER. Nodes fold the same block at different times — mined, gossiped, backfilled,
        // adopted — so an order-dependent accumulator makes two nodes with identical chains advertise
        // different values, and a proof built against one cannot verify against the other. Measured live
        // before this was fixed: A `295b894e…` vs B `3668356a…` on the same chain.
        let mut swapped = genesis;
        for i in [1u64, 0] {
            swapped = note_membership_step_new_acc(swapped, r(i));
        }
        let mut ordered = genesis;
        for i in [0u64, 1] {
            ordered = note_membership_step_new_acc(ordered, r(i));
        }
        assert_eq!(swapped, ordered, "arrival order must NOT change the accumulator");

        // A MISSING block must change it too, or a prover could quietly omit history.
        let mut missing = genesis;
        for i in (0..512u64).filter(|i| *i != 300) {
            missing = note_membership_step_new_acc(missing, r(i));
        }
        assert_ne!(deep, missing, "dropping a block must change the accumulator");
    }

    #[test]
    fn a_carrier_refuses_to_certify_a_block_it_never_folded() {
        // THE SOUNDNESS HINGE, and it has to be tested with a carrier that COULD otherwise certify: one that
        // holds a valid membership proof. An earlier version of this test never attached one, so `finalize`
        // returned None because there was nothing to fold at all — it passed with every gate deleted, which
        // makes it no test. Attach a real proof, then fold a chain that does NOT contain the note's block.
        let leaf = r(11);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(100 + i)).collect();
        let dirs = vec![false, true, false, false, true, true, false, true];
        let our_root = refold_in_block(leaf, &sibs, &dirs);

        let mut c = NoteMembershipCarrier::new(leaf, our_root, [0u64; DIGEST_LIMBS], r(7), r(0x363));
        assert!(c.attach_membership(leaf, &sibs, &dirs), "the membership proof is valid and attached");
        assert!(c.finalize().is_none(), "nothing is certifiable before any block is folded");

        // Fold a chain of OTHER blocks. The carrier holds a genuine proof, so only the claimed-block gate
        // stands between it and certifying membership in a chain that never held the note.
        for i in crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]) {
            let _ = c.step(r(i));
        }
        assert!(!c.saw_claimed_block(), "our block was never in this chain");
        assert!(
            c.finalize().is_none(),
            "a carrier holding a valid proof must NOT certify membership in a chain that never folded its block"
        );

        // ...and once the claimed block IS folded, it certifies — so the gate blocks the false case only.
        assert!(c.step(our_root), "folding our block must succeed");
        assert!(c.saw_claimed_block());
        assert!(c.finalize().is_some(), "membership must certify once the block is genuinely in the chain");
    }

    #[test]
    fn the_in_block_refold_is_a_constant_depth_check_that_rejects_a_forged_sibling() {
        // The private half stays constant: a note's path to its OWN block root is IN_BLOCK_DEPTH levels —
        // log2 of the production 256 cover — regardless of chain height, and it is derived from the DA layer
        // rather than accumulated by watching a window go by.
        let leaf = r(11);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(100 + i)).collect();
        let dirs = vec![false, true, false, false, true, true, false, true];
        assert_eq!(sibs.len(), IN_BLOCK_DEPTH, "the copath is the production cover depth");
        let root = refold_in_block(leaf, &sibs, &dirs);
        assert_eq!(root, refold_in_block(leaf, &sibs, &dirs), "the refold is deterministic");

        let mut forged = sibs.clone();
        forged[3] = r(999);
        assert_ne!(refold_in_block(leaf, &forged, &dirs), root, "a forged sibling must not refold to the root");

        // A different note under the same path is a different root — the leaf is genuinely bound.
        assert_ne!(refold_in_block(r(12), &sibs, &dirs), root, "the leaf is bound into the root");

        // Flipping a direction bit is also a different claim.
        let mut flipped = dirs.clone();
        flipped[0] = !flipped[0];
        assert_ne!(refold_in_block(leaf, &sibs, &flipped), root, "direction bits are part of the claim");
    }

    // 2026-09-27: `the_verifier_rejects_a_transition_that_was_never_honestly_folded` tested the residual helper of
    // the retired recursive fold (`note_membership_acc_residual`, deleted with `verify_note_membership_chain`).
    // The accumulator transition it guarded is now computed natively by both sides (`note_membership_step_new_acc`)
    // and compared by the node; there is no in-circuit residual to test.

    #[test]
    fn the_membership_step_proves_a_real_copath_and_refuses_a_false_one() {
        // The per-block claim the fold lifts. `None` here is not an error path to be worked around — it is the
        // gate: a prover must not be able to assert membership for a note the block does not contain.
        let leaf = r(11);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(100 + i)).collect();
        let dirs = vec![false, true, false, false, true, true, false, true];
        let root = refold_in_block(leaf, &sibs, &dirs);

        let proof = prove_note_member_step_bytes(leaf, &sibs, &dirs, root, r(7), r(0x363));
        assert!(proof.is_some(), "an honest copath must prove");
        assert!(!proof.as_ref().unwrap().is_empty(), "the proof must have content");

        // A root the copath does not reach is unprovable — the false claim cannot be dressed up.
        assert!(
            prove_note_member_step_bytes(leaf, &sibs, &dirs, r(4242), r(7), r(0x363)).is_none(),
            "a copath that does not reach the claimed root must NOT prove"
        );
        // Same for a forged sibling and a flipped direction bit.
        let mut forged = sibs.clone();
        forged[2] = r(777);
        assert!(prove_note_member_step_bytes(leaf, &forged, &dirs, root, r(7), r(0x363)).is_none(), "a forged sibling must not prove");
        let mut flipped = dirs.clone();
        flipped[5] = !flipped[5];
        assert!(prove_note_member_step_bytes(leaf, &sibs, &flipped, root, r(7), r(0x363)).is_none(), "a flipped bit must not prove");
        // And a different note under the same path.
        assert!(prove_note_member_step_bytes(r(12), &sibs, &dirs, root, r(7), r(0x363)).is_none(), "another note must not prove");
        // A short path is not a path — the depth is fixed by the production cover width.
        assert!(prove_note_member_step_bytes(leaf, &sibs[..4], &dirs[..4], root, r(7), r(0x363)).is_none(), "a short copath must not prove");
    }

    #[test]
    fn the_folded_proof_size_does_not_grow_with_the_number_of_blocks_folded() {
        // EMPIRICAL, not asserted. A ratio or a "should be constant" comment is not proof of O(1) — the size
        // has to be MEASURED at increasing heights and shown not to move. This is the exact axis that caught
        // the previous attempt: compressed carried witnesses went 64,704 B -> 96,544 B over six blocks, so the
        // constant shrank while the AXIS survived. If this fold has the same flaw, this test says so.
        //
        // PRODUCTION-SCALE-REVIEWED: the loop bound is a chain HEIGHT (blocks folded), not a cover count.
        let leaf = r(11);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(100 + i)).collect();
        let dirs = vec![false, true, false, false, true, true, false, true];
        let our_root = refold_in_block(leaf, &sibs, &dirs);

        let mut c = NoteMembershipCarrier::new(leaf, our_root, [0u64; DIGEST_LIMBS], r(7), r(0x363));
        assert!(c.attach_membership(leaf, &sibs, &dirs), "the membership step must prove before folding");

        let mut sizes: Vec<usize> = Vec::new();
        // Fold: two blocks before ours, ours, then more after — the note's block is not the tip.
        let chain: Vec<Digest> = vec![r(1), r(2), our_root, r(3), r(4), r(5)];
        for (i, root) in chain.iter().enumerate() {
            assert!(c.step(*root), "step {i} must fold");
            if let Some((proof, _, _, _)) = c.finalize() {
                eprintln!("[fold] after block {i}: proof = {} bytes", proof.len());
                sizes.push(proof.len());
            }
        }
        assert!(
            sizes.len() >= 3,
            "the fold must produce a proof at our block and keep producing one after it — got {} sizes",
            sizes.len()
        );
        // The property is NO GROWTH WITH HEIGHT, not byte-identity: field elements encode to variable length,
        // so a few bytes of jitter either way is encoding, not an axis. The failure this guards is the one
        // previously measured on carried witnesses — 64,704 -> 96,544 B, a 1.49x rise over six blocks. A 1%
        // ceiling catches any real growth while ignoring jitter; note the observed direction is DOWNWARD.
        let first = sizes[0] as f64;
        let last = *sizes.last().unwrap() as f64;
        let peak = *sizes.iter().max().unwrap() as f64;
        assert!(
            last / first <= 1.01,
            "the folded proof GREW with height — measured {sizes:?} ({:.3}x). That is the banned axis.",
            last / first
        );
        assert!(
            peak / first <= 1.01,
            "the folded proof peaked above its start — measured {sizes:?} ({:.3}x)",
            peak / first
        );
    }

    #[test]
    fn the_per_block_fold_step_costs_the_same_at_every_height() {
        // TIME is an axis too. A fold whose SIZE is constant but whose per-step COST rises with height is
        // still O(chain) — and a wallet joining a tall chain would pay it all at once. Measure the step at
        // increasing depth and require the late steps to cost what the early ones do.
        //
        // PRODUCTION-SCALE-REVIEWED: the loop bound is a chain HEIGHT (blocks folded), not a cover count.
        use std::time::Instant;
        let leaf = r(11);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(100 + i)).collect();
        let dirs = vec![false, true, false, false, true, true, false, true];
        let our_root = refold_in_block(leaf, &sibs, &dirs);
        let mut c = NoteMembershipCarrier::new(leaf, our_root, [0u64; DIGEST_LIMBS], r(7), r(0x363));
        assert!(c.attach_membership(leaf, &sibs, &dirs));
        assert!(c.step(our_root), "seed the fold at our block");

        let mut times: Vec<u128> = Vec::new();
        for i in 0..24u64 {
            let t = Instant::now();
            assert!(c.step(r(1000 + i)), "step {i} must fold");
            times.push(t.elapsed().as_micros());
        }
        let early: u128 = times[..4].iter().sum::<u128>() / 4;
        let late: u128 = times[times.len() - 4..].iter().sum::<u128>() / 4;
        eprintln!("[fold-time] early {early}us  late {late}us  over {} steps", times.len());
        assert!(
            late <= early.max(1) * 3,
            "per-step fold cost ROSE with height: early {early}us -> late {late}us. That is O(chain) in time."
        );
    }

    #[test]
    fn the_step_gate_binds_the_commitment_to_the_leaf_it_actually_refolds() {
        // ⭐ THE CROSS-BIND, FORGED AGAINST THE REAL AIR.
        //
        // `leaf_commit` is the only thing about the note a verifier sees. If the gate does not CONSTRAIN it to
        // the leaf the trace actually refolds, a prover can hold a valid membership proof for note X and
        // label it with note Y's commitment — "some note is a member" wearing the name of a note it is not.
        // That is exactly what would let a carrier authorise the wrong spend.
        //
        // An earlier version of this test only compared native `note_leaf_commitment` values and asserted two
        // proofs differed. It passed with the in-circuit weld DELETED — it never exercised the constraint at
        // all. This one drives the AIR directly with an HONEST trace and a LIED-ABOUT commitment, which is the
        // only thing the constraint can refuse.
        let leaf = r(11);
        let binder = r(77);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|i| r(200 + i)).collect();
        let dirs = vec![true, false, true, true, false, false, true, false];
        let root = refold_in_block(leaf, &sibs, &dirs);
        let blind = r(0x363);
        let honest_commit = note_leaf_commitment(leaf, binder, blind);

        // Rebuild the honest trace exactly as the prover does.
        // ⭐ THE TRACE COMES FROM THE PROVER'S OWN BUILDER, not a hand-rolled copy. The previous version
        // of this test re-implemented the 54-column layout inline; when the layout moved to real permutation
        // blocks that copy would have gone stale and kept "passing" against a shape nothing else uses.
        let build_cols = || member_step_cols(leaf, &sibs, &dirs, binder, blind);
        let ea = |v: Digest| -> [Ea4; DIGEST_LIMBS] { core::array::from_fn(|c| Fa4::from_u64(kred(v[c])).into()) };

        // CONTROL: the honest trace under the HONEST commitment proves. Without this the negative below
        // would be meaningless — a subject that could not have succeeded anyway proves nothing.
        let honest = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            build_cols(),
            move |g: Ea4| NoteMemberStepGate {
                gamma: g,
                leaf_commit: ea(honest_commit),
                binder: ea(binder),
                block_root: ea(root),
            },
            &note_member_step_bind(honest_commit, root),
        );
        let honest = honest.expect("the honest trace under its true commitment MUST prove");
        assert!(
            crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
                &honest,
                move |g: Ea4| NoteMemberStepGate {
                    gamma: g,
                    leaf_commit: ea(honest_commit),
                    binder: ea(binder),
                    block_root: ea(root),
                },
                &note_member_step_bind(honest_commit, root),
                crate::whir_rec_block::declared_direct_shape_for_tests(&honest),
            ),
            "and it VERIFIES — otherwise the negatives below prove nothing"
        );

        // FORGERY: same honest path, same witnessed leaf — but the gate is told the commitment belongs to a
        // DIFFERENT note. The weld `Poseidon(leaf, binder) == leaf_commit` is the only thing standing here.
        let lie = note_leaf_commitment(r(12), binder, blind);
        assert_ne!(lie, honest_commit, "the two notes really do commit differently");
        let forged = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            build_cols(),
            move |g: Ea4| NoteMemberStepGate {
                gamma: g,
                leaf_commit: ea(lie),
                binder: ea(binder),
                block_root: ea(root),
            },
            &note_member_step_bind(lie, root),
        );
        // The prover does not fail-closed here — it will happily emit bytes for an unsatisfied trace. The
        // VERIFIER is the gate, so that is where the claim has to be tested.
        let forged_ok = forged.map_or(false, |bytes| {
            crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
                &bytes,
                move |g: Ea4| NoteMemberStepGate {
                    gamma: g,
                    leaf_commit: ea(lie),
                    binder: ea(binder),
                    block_root: ea(root),
                },
                &note_member_step_bind(lie, root),
                crate::whir_rec_block::declared_direct_shape_for_tests(&bytes),
            )
        });
        assert!(
            !forged_ok,
            "a membership proof labelled with ANOTHER note's commitment must NOT verify — otherwise one \
             valid proof can be presented for a note it is not about"
        );

        // FORGED BINDER: the same note under a binder the trace was not built for must also fail, which is
        // what makes a carrier non-replayable into another transaction.
        let wrong_binder = r(78);
        let replay = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            build_cols(),
            move |g: Ea4| NoteMemberStepGate {
                gamma: g,
                leaf_commit: ea(note_leaf_commitment(leaf, wrong_binder, blind)),
                binder: ea(wrong_binder),
                block_root: ea(root),
            },
            &note_member_step_bind(note_leaf_commitment(leaf, wrong_binder, blind), root),
        );
        let replay_ok = replay.map_or(false, |bytes| {
            crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
                &bytes,
                move |g: Ea4| NoteMemberStepGate {
                    gamma: g,
                    leaf_commit: ea(note_leaf_commitment(leaf, wrong_binder, blind)),
                    binder: ea(wrong_binder),
                    block_root: ea(root),
                },
                &note_member_step_bind(note_leaf_commitment(leaf, wrong_binder, blind), root),
                crate::whir_rec_block::declared_direct_shape_for_tests(&bytes),
            )
        });
        assert!(!replay_ok, "a trace built for one binder must not verify under another");
    }

    #[test]
    fn an_empty_proof_never_verifies() {
        // Fail-closed: absence of a proof is never success.
        assert!(!verify_note_membership_one_step(&[], note_leaf_commitment(r(11), r(7), r(0x363)), r(7), r(1)));
    }
}

#[cfg(test)]
mod capacity_free_membership_proof {
    use super::*;

    /// A distinct, deterministic block root per height.
    fn root_at(i: u64) -> Digest {
        poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[kred(0x51ED_2701_A33B_C0DE), i]), crate::poseidon2_compress::lanes_of(&[i, i ^ 0xff, i, i]))
    }

    /// Fold a chain of `n` block roots with the wallet's note living in block `at`, and return the ONE-STEP
    /// certificate the spend carries with its publics: `(proof_bytes, leaf_commit, binder, our_root)`.
    fn fold_chain(n: u64, at: u64) -> (Vec<u8>, Digest, Digest, Digest) {
        let genesis_acc = crate::poseidon2_compress::lanes_of(&[7u64, 7, 7, 7]);
        let leaf = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let binder = crate::poseidon2_compress::lanes_of(&[5u64, 5, 5, 5]);
        // A REAL in-block copath: a CONSTANT IN_BLOCK_DEPTH levels (log2 of the fixed 256-slot block shape).
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|s| crate::poseidon2_compress::lanes_of(&[s + 1, s + 2, s + 3, s + 4])).collect();
        let dirs: Vec<bool> = (0..IN_BLOCK_DEPTH).map(|s| s % 2 == 0).collect();
        let our_root = refold_in_block(leaf, &sibs, &dirs);

        let mut c = NoteMembershipCarrier::new(leaf, our_root, genesis_acc, binder, crate::poseidon2_compress::lanes_of(&[0x363u64, 1, 2, 3]));
        assert!(c.attach_membership(leaf, &sibs, &dirs), "the in-block copath refolds to the claimed root");
        for i in 0..n {
            let r = if i == at { our_root } else { root_at(i) };
            assert!(c.step(r), "block {i} folds");
        }
        let (proof, _acc, _tip_prev, _tip_root) = c.finalize().expect("a folded chain certifies");
        (proof, c.leaf_commitment(), binder, our_root)
    }

    /// ⭐⭐⭐ NO CAPACITY CEILING, AND NO HISTORY TERM — the proof the O(1) cardinal demands.
    ///
    /// This is the membership shape that replaces a fixed-depth Merkle tree. A depth-D tree DIES at 2^D
    /// leaves — a capacity WINDOW, and when it fills no note can ever be appended again (user 2026-08-14:
    /// "a window bug, funds loss bug and a chain killer"). Widening D only moves the expiry date, and an
    /// unbounded MMR trades the window for a copath that grows with N, which is equally banned.
    ///
    /// The fold has NEITHER failure mode:
    ///   * CAPACITY — the accumulator is a field element folded `acc_h = H(dom, H(acc_{h-1}, root_h))`. There
    ///     is no leaf budget to exhaust: it accepts block 10 and block 10^12 identically.
    ///   * SIZE — the running proof is a fixed-point recursive shape, so its BYTE LENGTH is f(λ, fixed
    ///     protocol constants) with NO N term. Asserted EQUAL, not merely "close", at two very different
    ///     chain lengths — a 16x span. Any per-block or per-leaf term would show as a difference here.
    /// The private half stays a CONSTANT `IN_BLOCK_DEPTH` copath (log2 of the fixed 256-slot block), which is
    /// f(a protocol constant), not f(history).
    ///
    /// cons: none — this is a test; it measures an existing fold and adds no runtime path.
    #[test]
    fn the_membership_proof_carries_no_chain_length_term_at_any_chain_length() {
        let (short_proof, short_commit, short_binder, short_root) = fold_chain(16, 5);
        let (mid_proof, _, _, _) = fold_chain(64, 5);
        let (long_proof, long_commit, long_binder, long_root) = fold_chain(256, 5);

        // The certificate is the ONE-STEP carrier (2026-09-27: the recursive fold is retired), a blinded committed
        // carrier at a FIXED shape: its length is f(λ, fixed protocol constants) with no history term at all, so
        // equality — not "close" — is the claim. Every field element is 4 wire bytes (2026-09-11), so the length
        // cannot leak which values are zero either. MEASURED: 132,346 B at every depth and every chain length.
        let sizes = [short_proof.len(), mid_proof.len(), long_proof.len()];
        assert!(
            sizes[0] == sizes[1] && sizes[1] == sizes[2],
            "NO N TERM: the one-step carrier must be byte-for-byte the same length at N=16/64/256 ({sizes:?})"
        );

        // Both certify — the chain's length is not a parameter of the statement.
        assert!(
            verify_note_membership_one_step(&short_proof, short_commit, short_binder, short_root),
            "the 16-block chain's membership proof verifies"
        );
        assert!(
            verify_note_membership_one_step(&long_proof, long_commit, long_binder, long_root),
            "the 256-block chain's membership proof verifies — capacity is not a parameter of this design"
        );
    }

    /// ⛔ SOUNDNESS IS NOT TRADED FOR CAPACITY. A capacity-free membership proof is worthless if it also
    /// admits notes that are not members, so every rejection path is asserted at the LONG chain length.
    #[test]
    fn a_forged_membership_claim_is_refused_at_any_chain_length() {
        let (proof, commit, binder, root) = fold_chain(256, 5);
        assert!(verify_note_membership_one_step(&proof, commit, binder, root), "honest");

        let other = crate::poseidon2_compress::lanes_of(&[99u64, 98, 97, 96]);
        assert!(
            !verify_note_membership_one_step(&proof, other, binder, root),
            "a DIFFERENT note's leaf commitment is refused — the leaf is bound into the carrier"
        );
        assert!(!verify_note_membership_one_step(&proof, commit, other, root), "a forged binder is refused");
        assert!(!verify_note_membership_one_step(&proof, commit, binder, other), "a forged block root is refused");
        assert!(!verify_note_membership_one_step(&[], commit, binder, root), "empty refused");
    }

    /// ⛔ A NOTE WHOSE BLOCK IS NOT IN THE CHAIN CANNOT CERTIFY — the fold is not a rubber stamp. Without
    /// this, "capacity-free" would just mean "accepts anything at any length".
    #[test]
    fn a_note_whose_block_never_appears_cannot_certify_however_long_the_chain_runs() {
        let genesis_acc = crate::poseidon2_compress::lanes_of(&[7u64, 7, 7, 7]);
        let leaf = crate::poseidon2_compress::lanes_of(&[11u64, 22, 33, 44]);
        let sibs: Vec<Digest> = (0..IN_BLOCK_DEPTH as u64).map(|s| crate::poseidon2_compress::lanes_of(&[s + 1, s + 2, s + 3, s + 4])).collect();
        let dirs: Vec<bool> = (0..IN_BLOCK_DEPTH).map(|s| s % 2 == 0).collect();
        let our_root = refold_in_block(leaf, &sibs, &dirs);
        let mut c = NoteMembershipCarrier::new(leaf, our_root, genesis_acc, crate::poseidon2_compress::lanes_of(&[5u64, 5, 5, 5]), crate::poseidon2_compress::lanes_of(&[0x363u64, 1, 2, 3]));
        assert!(c.attach_membership(leaf, &sibs, &dirs));
        for i in 0..256u64 {
            assert!(c.step(root_at(i)), "block {i} folds");
        }
        assert!(
            c.finalize().is_none(),
            "256 folded blocks, none of them ours ⇒ NO certificate — length never substitutes for membership"
        );
    }
}

#[cfg(test)]
mod brc_falsifiable_step {
    use super::*;

    /// ⚠️⚠️⚠️ THE LOAD-BEARING MEASUREMENT FOR THE BRC COLD-RESTORE DESIGN — run BEFORE any consensus edit.
    ///
    /// The design ([[project_brc_instant_cold_restore_design]]) says a wallet can restore at ANY offline age
    /// by opening a commitment to the block-root vector instead of folding it. That rests on ONE claim:
    ///
    ///     the proof over an N-root vector carries NO N TERM.
    ///
    /// If it grows with N, the design is WRONG and must be said so — a commitment whose opening tracks the
    /// vector length is the same banned growth as the copath it replaces, wearing a new name.
    ///
    /// O1-DEFINITION-REVIEWED: measured as a DETERMINISTIC COUNTER (proof BYTES) at two very different N.
    /// Not wall-clock, not a ratio — a ratio compares two points on the same curve and says nothing about its
    /// shape. ⚠️ I asserted byte-EQUALITY three times today and was wrong each time; the correct claim is
    /// "no per-item term", asserted with arithmetic that separates encoding variance from a real term.
    #[test]
    fn the_block_root_vector_proof_carries_no_vector_length_term() {
        // A committed block-root vector of height H: 4 limb columns + a live selector, exactly the fixed
        // shape a BRC would commit. Height is the ONLY thing that varies between the two measurements.
        // ⛔ WAS `(0..5)` COLUMNS WITH THE SELECTOR AT `cols[4]` — four digest limbs plus a selector,
        // which is the retired width. The shape is DERIVED so the measurement keeps measuring the thing
        // it names (a fixed-shape commitment) rather than panicking on its own trace.
        let build = |h: usize| -> Vec<Vec<Fa4>> {
            let mut cols: Vec<Vec<Fa4>> =
                (0..BRC_PROBE_COLS).map(|_| vec![Fa4::ZERO; h]).collect();
            for i in 0..h {
                let r = poseidon_pair_native(crate::poseidon2_compress::lanes_of(&[kred(0x51ED_2701_A33B_C0DE), i as u64]), crate::poseidon2_compress::lanes_of(&[i as u64, 7, 9, 11]));
                for c in 0..DIGEST_LIMBS {
                    cols[c][i] = Fa4::from_u64(kred(r[c]));
                }
                cols[BRC_PROBE_SEL][i] = Fa4::ONE;
            }
            cols
        };
        let prove_at = |h: usize| -> Option<usize> {
            let cols = build(h);
            let make = |_g: Ea4| SparseFoldGateShim;
            crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
                cols,
                make,
                &[Fa4::from_u64(h as u64)],
            )
            .map(|b| b.len())
        };
        let small = prove_at(1 << 6).expect("commit a 64-root vector");
        let large = prove_at(1 << 12).expect("commit a 4096-root vector");
        let span = if large > small { large - small } else { small - large };
        eprintln!("[brc-measure] vector proof bytes: N=64 -> {small} B, N=4096 -> {large} B (span {span} B)");
        eprintln!("[brc-measure] a 1-byte-per-root term would span >= {} B", (1 << 12) - (1 << 6));

        // (a) NO LINEAR TERM — a per-root cost would spend >= N2-N1 bytes. It does not.
        assert!(
            span < ((1 << 12) - (1 << 6)),
            "a per-root term would make this proof track the vector length outright"
        );

        // (b) ⛔ BUT A **LOG N** TERM IS PRESENT, AND log N IS BANNED. 64x the roots costs ~224 B — six extra
        //     folding rounds. MEASURED, and it is the finding that CORRECTS the BRC plan: a RAW WHIR opening
        //     is polylog, so serving one to a wallet would swap the banned copath for a banned growth axis,
        //     which is the cardinal-swap this project keeps catching ([[feedback_no_cardinal_swap_no_escape]]).
        //     The fix is NOT a bigger allowance — it is to RECURSIVELY FOLD the opening into the fixed-point
        //     shape the decider already produces. That shape is measured flat: `capacity_free_membership_proof`
        //     gives 9,362 B at N=16 vs 9,341 B at N=256 (non-monotonic, no term).
        //     This assertion PINS the log term so nobody later reads (a) alone as "flat".
        assert!(
            span > 64,
            "a raw opening is expected to carry a LOG N term (measured ~224 B across a 64x span). If this ever \
             reads flat, re-measure before believing it — the whole BRC design hinges on whether the opening \
             is folded or raw"
        );
    }

    /// The gate the measurement commits under — a bare live-row selector, so the trace SHAPE is what is being
    /// measured and no constraint work is smuggled into the size.
    /// The probe trace: one digest's limbs, then the live-row selector.
    const BRC_PROBE_SEL: usize = DIGEST_LIMBS;
    const BRC_PROBE_COLS: usize = BRC_PROBE_SEL + 1;

    struct SparseFoldGateShim;
    impl crate::air_zerocheck::AirConstraint for SparseFoldGateShim {
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            local[BRC_PROBE_SEL] * (local[BRC_PROBE_SEL] - Ea4::ONE) // selector ∈ {0,1}
        }
    }
}

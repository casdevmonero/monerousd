//! MonerousD Protocol — THE SLOT LEDGER ROW (padding spec v2 §2 + §2.6, decider half; lane-recursion, 2026-09-30).
//!
//! ⛔ THE LEAK THIS CLOSES (docs/NOTE-TRANSITION-TUPLE-PADDING-SPEC.md §1): a block's note transition publishes one
//! tuple per REAL spend, so the wire list's length is the block's real spend count. The proof was already padded to a
//! constant shape (`settlement_delta::DELTA_FIXED_SLOTS`); the LIST beside it was not.
//!
//! THE SHAPE: one list of `N = 128` rows, constant, in canonical order. Every row owns two TAG cells and two NOTE cells,
//! and nothing on the wire says which rows are real. Per row the step table carries, beside the bound WHIR step of a
//! carrier (§2.6: a real spend's, or a REPLICA of the last real one), this module's EXTENSION:
//!
//! - `is_spend` (hidden): the row publishes its carrier's absorbed statement — `tag0 ← nullifier`, `out0'`, `out1'`,
//!   `lc'`, `D'` — as ONE bit switches every published cell (a producer can never publish a spend's nullifier without
//!   its outputs; it can only leave the whole spend out, which omission already allows).
//! - otherwise every published cell is COVER (`P(domain ‖ seed ‖ slot)` over the header seed, in circuit) or JUSTIFIED
//!   (a public bit — `j` for a note cell, `t` for a tag cell — that the DOOR recomputes from the block's other verified
//!   objects: mint/DEX/credit outputs for notes, the objects' own nullifiers for tags; in circuit a justified cell has
//!   no law, exactly as §2.3 states for notes).
//! - `tag1` of a spend row is cover. ⛔ The device-slot CLAIM does NOT live here (DB-329 §7b, refuted by the wallet lane
//!   2026-09-30 05:38): the rows are proven by the BLOCK PRODUCER, so a claim's `(slot_key, d)` would have to travel to
//!   it, and anyone holding them enumerates every claim of that seed. The claim law belongs in the SPENDER's own carrier
//!   (it publishes `P(SLOT_CLAIM_DOMAIN ‖ d, key)` as part of its statement); [`slot_claim_native`] is its one spelling.
//! - the header seed is bound on EVERY row by `P(HEADER_SEED_DOMAIN ‖ seed) = cover_seed_commit`, the one new public
//!   word (C2, spelled per row so the wide step table stays row-local — §2.6).
//! - C1 (unselected columns are forced, never free): every witness a class does not use is forced to zero by the
//!   selector, so the free-witness census reads the same answer under every selector value.
//!
//! This file is the ROW: its layout, its laws, its trace filler, the native derivations the node's door shares, and
//! a standalone gate over one row for the RED-first pins and the strict censuses. The aggregate integration lives in
//! `settlement_delta.rs` (`prove_block_ledger_transition` / `verify_block_ledger_transition`).

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::{lanes_of, Digest, DIGEST_LANES};
use p3_field::PrimeCharacteristicRing;

/// The list's constant length. DERIVED: 256 header tag slots / 2 tag cells per row = 256 header note slots / 2 note
/// cells per row. Pinned against the node's block constants by the node crate.
pub const SLOT_LEDGER_ROWS: usize = 128;
/// Cells per row of each kind — the derivation above, spelled.
pub const CELLS_PER_ROW: usize = 2;
const _: () = assert!(SLOT_LEDGER_ROWS * CELLS_PER_ROW == 256, "128 rows × 2 cells = the block's 256 slots");

/// Poseidon domains (canonical field lanes: every one is below the KoalaBear order).
pub const COVER_NF_DOMAIN: u64 = 0x434f_5654; // "COVT" — a cover TAG
pub const COVER_CM_DOMAIN: u64 = 0x434f_5643; // "COVC" — a cover NOTE commitment
pub const HEADER_SEED_DOMAIN: u64 = 0x4853_4544; // "HSED" — the header seed's commitment
pub const COVER_LC_DOMAIN: u64 = 0x434f_564c; // "COVL" — a cover row's CROSS-BIND (padding v2 §9.2)
pub const SLOT_CLAIM_DOMAIN: u64 = 0x534c_4f54; // "SLOT" — a device-slot claim tag (the SPENDER's law, not this row's)

// ── The row EXTENSION, offsets relative to its base ──────────────────────────────────────────────────────────────
pub const SL_IS_SPEND: usize = 0;
pub const SL_J0: usize = 1;
pub const SL_J1: usize = 2;
pub const SL_T0: usize = 3;
pub const SL_T1: usize = 4;
/// ⭐ padding spec §18 — `is_tail` (hidden): a PAIR row of a stated spend other than its head. Its two tag cells are the
/// spend's constant-width tags `2p, 2p+1` as FREE witnesses here, bound by the tag ledger (`crate::tag_ledger`: the
/// carrier's chain over 16 rows) and the door's per-row pair-digest equality; its notes, `lc` and `D` are a cover row's.
/// No public bit names it — the flags of a tail row are zero, as a cover row's are.
pub const SL_IS_TAIL: usize = 5;
/// The header seed (hidden), `DIGEST_LANES` lanes.
pub const SL_SEED: usize = 6;
/// Cover slot indices (hidden): tag0, tag1, note0, note1.
pub const SL_SLOT_T0: usize = SL_SEED + DIGEST_LANES;
pub const SL_SLOT_T1: usize = SL_SLOT_T0 + 1;
pub const SL_SLOT_N0: usize = SL_SLOT_T1 + 1;
pub const SL_SLOT_N1: usize = SL_SLOT_N0 + 1;
/// ⭐ padding v2 §9.2 — the cover row's cross-bind slot (hidden; distinct per row, the planner's; zero on a spend row).
pub const SL_SLOT_LC: usize = SL_SLOT_N1 + 1;
/// Justified values (public by the chain digest, free in circuit; zero unless the matching bit is set).
pub const SL_JUST_T0: usize = SL_SLOT_LC + 1;
pub const SL_JUST_T1: usize = SL_JUST_T0 + DIGEST_LANES;
pub const SL_JUST_N0: usize = SL_JUST_T1 + DIGEST_LANES;
pub const SL_JUST_N1: usize = SL_JUST_N0 + DIGEST_LANES;
/// §18 — a tail row's two tags (hidden; zero unless `is_tail`, C1).
pub const SL_TAIL_T0: usize = SL_JUST_N1 + DIGEST_LANES;
pub const SL_TAIL_T1: usize = SL_TAIL_T0 + DIGEST_LANES;
/// ⭐ padding v2 §9.1 — a cover row's filing digest `D`: the PUBLIC filing function of the row's own published notes
/// (`oli::filing_d` over the block's `oli_tags`), computed by the producer and checked natively by the door on EVERY
/// row, so the `D` column follows one public rule on both classes. Zero on a spend row (C1); read by B8 on a cover row.
pub const SL_COVER_D: usize = SL_TAIL_T1 + DIGEST_LANES;
/// The PUBLISHED block: 8 digests — `tag0 ‖ tag1 ‖ out0' ‖ out1' ‖ lc' ‖ D' ‖ flags ‖ 0`, the row the chain hashes.
/// `flags` carries `j0, j1, t0, t1` in its first four lanes. Eight digests keep the chain's duplexing stride
/// (`settlement_delta::DIGESTS_PER_TUPLE`).
pub const SL_PUB: usize = SL_COVER_D + DIGEST_LANES;
pub const PUB_DIGESTS: usize = 8;
pub const PUB_TAG0: usize = 0;
pub const PUB_TAG1: usize = 1;
pub const PUB_OUT0: usize = 2;
pub const PUB_OUT1: usize = 3;
pub const PUB_LC: usize = 4;
pub const PUB_D: usize = 5;
pub const PUB_FLAGS: usize = 6;
/// Six whole Poseidon2 blocks: cover tag0, cover tag1, cover note0, cover note1, the seed commit, the cover cross-bind.
pub const SL_B_T0: usize = SL_PUB + PUB_DIGESTS * DIGEST_LANES;
pub const SL_B_T1: usize = SL_B_T0 + crate::pow_pq_air::P2_COLS;
pub const SL_B_N0: usize = SL_B_T1 + crate::pow_pq_air::P2_COLS;
pub const SL_B_N1: usize = SL_B_N0 + crate::pow_pq_air::P2_COLS;
pub const SL_B_SEED: usize = SL_B_N1 + crate::pow_pq_air::P2_COLS;
pub const SL_B_LC: usize = SL_B_SEED + crate::pow_pq_air::P2_COLS;
/// The extension's width.
pub const SL_EXT_COLS: usize = SL_B_LC + crate::pow_pq_air::P2_COLS;

/// The ABSORBED statement a row's carrier proved — the first six digests of the bound step's tuple, in the order
/// `validity_public_bind_with_commit` writes them. These are INDICES into that six-digest tuple, never counts.
pub const ABS_OUT0: usize = 0;
pub const ABS_OUT1: usize = 1;
pub const ABS_NULLIFIER: usize = 2; // PRODUCTION-SCALE-REVIEWED: the INDEX of the nullifier digest among the six absorbed digests, not a cover count
pub const ABS_LC: usize = 3;
pub const ABS_D: usize = 4;
/// DB-329 §7e: the spend's device-slot claim tag — proven by the SPENDER's carrier under its own witness (`SV_CLAIM_*`),
/// published by a spend row as its `tag1`. The producer never holds the claim's key.
pub const ABS_TAG1: usize = 5;
pub const ABS_DIGESTS: usize = 6;

fn f(v: u64) -> Fa4 {
    Fa4::from_u64(v)
}
fn e(v: u64) -> Ea4 {
    Ea4::from(f(v))
}
fn e8(d: &Digest) -> [Ea4; DIGEST_LANES] {
    core::array::from_fn(|c| e(d[c]))
}

// ── Native derivations — ONE spelling, shared with the node's door and the wallet's cover regeneration ──────────
/// A cover TAG cell: `P(COVER_NF_DOMAIN ‖ slot ‖ 0… , seed)`.
#[must_use]
pub fn cover_tag_native(seed: Digest, slot: u64) -> Digest {
    crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[COVER_NF_DOMAIN, slot]), seed)
}
/// A cover NOTE commitment cell: `P(COVER_CM_DOMAIN ‖ slot ‖ 0… , seed)` — no opening under the note domain, so it can
/// be neither received nor spent.
#[must_use]
pub fn cover_note_native(seed: Digest, slot: u64) -> Digest {
    crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[COVER_CM_DOMAIN, slot]), seed)
}
/// A cover row's CROSS-BIND cell: `P(COVER_LC_DOMAIN ‖ slot ‖ 0… , seed)` — uniform like a spend's blinded
/// `P(P(leaf, nf), r)`, so the `lc` column is never zero on one class and random on the other (padding v2 §8–§9.2).
#[must_use]
pub fn cover_lc_native(seed: Digest, slot: u64) -> Digest {
    crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[COVER_LC_DOMAIN, slot]), seed)
}
/// The header seed's public commitment: `P(HEADER_SEED_DOMAIN ‖ 0… , seed)`.
#[must_use]
pub fn seed_commit_native(seed: Digest) -> Digest {
    crate::nullifier_insert_air::poseidon_pair_native(lanes_of(&[HEADER_SEED_DOMAIN]), seed)
}
/// A device-slot claim tag: `P(SLOT_CLAIM_DOMAIN ‖ d ‖ 0… , slot_key)` — deterministic per `(slot_key, d)`. The ONE
/// spelling for the SPENDER's carrier law (DB-329 §7b): a spend proves it under its own witness, so `(slot_key, d)` never
/// leaves the wallet.
#[must_use]
pub fn slot_claim_native(slot_key: Digest, d: u64) -> Digest {
    let (a, b) = slot_claim_preimage(slot_key, d);
    crate::nullifier_insert_air::poseidon_pair_native(a, b)
}

/// The Poseidon PAIR a claim tag is the image of: `(lanes(SLOT_CLAIM_DOMAIN, d), slot_key)`. DB-329 §7f: a send's
/// spend-or-decoy proof witnesses its claim row (row 1) as a REAL row over exactly this pair — the one spelling the
/// wallet uses, so the row and the carrier's claim law can never name two preimages.
#[must_use]
pub fn slot_claim_preimage(slot_key: Digest, d: u64) -> (Digest, Digest) {
    (lanes_of(&[SLOT_CLAIM_DOMAIN, d]), slot_key)
}

/// What a row's producer knows. Everything here is HIDDEN in the aggregate except through the published block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotLedgerWitness {
    pub is_spend: bool,
    /// §18: a stated spend's tail pair row (never with `is_spend`; justifies no tag; its tag slots are zero).
    pub is_tail: bool,
    /// The tail row's two tags; zero unless `is_tail` (C1).
    pub tail_t: [Digest; 2],
    /// Justified NOTE bits `(j0, j1)` and justified TAG bits `(t0, t1)`; all zero on a spend row.
    pub j: [bool; 2],
    pub t: [bool; 2],
    pub seed: Digest,
    /// Cover slots: `[tag0, tag1, note0, note1]`; a slot the class does not use MUST be 0 (C1).
    pub slots: [u64; 4],
    /// Justified values `[tag0, tag1]` and `[note0, note1]`; zero unless the matching bit is set (C1).
    pub just_t: [Digest; 2],
    pub just_n: [Digest; 2],
    /// The cover cross-bind slot ([`SL_SLOT_LC`]); 0 on a spend row (C1).
    pub slot_lc: u64,
    /// The cover row's filing digest ([`SL_COVER_D`]); zero on a spend row (C1).
    pub cover_d: Digest,
}

impl SlotLedgerWitness {
    /// A pure cover row over `seed`: slots as given, nothing justified.
    #[must_use]
    pub fn cover(seed: Digest, slots: [u64; 4]) -> Self {
        Self {
            is_spend: false,
            is_tail: false,
            tail_t: [[0; DIGEST_LANES]; 2],
            j: [false; 2],
            t: [false; 2],
            seed,
            slots,
            just_t: [[0; DIGEST_LANES]; 2],
            just_n: [[0; DIGEST_LANES]; 2],
            slot_lc: 0,
            cover_d: [0; DIGEST_LANES],
        }
    }
    /// A spend row: every cell is the carrier's own statement — `tag0` its nullifier, `tag1` its proven claim tag
    /// (DB-329 §7e), the notes its outputs — so it uses no cover slot at all.
    #[must_use]
    pub fn spend(seed: Digest) -> Self {
        Self { is_spend: true, ..Self::cover(seed, [0; 4]) }
    }
    /// §18 — a TAIL row: the spend's tags `2p, 2p+1` in its tag cells, cover notes at `note_slots`, nothing justified.
    #[must_use]
    pub fn tail(seed: Digest, tags: [Digest; 2], note_slots: [u64; 2]) -> Self {
        Self { is_tail: true, tail_t: tags, ..Self::cover(seed, [0, 0, note_slots[0], note_slots[1]]) }
    }
    /// Is every unused witness zero? The laws force it; the producer should never have to be told.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let z = [0u64; DIGEST_LANES];
        let ok_spend = !self.is_spend
            || (self.j == [false; 2] && self.t == [false; 2] && self.slots == [0; 4] && self.slot_lc == 0 && self.cover_d == z);
        let ok_tail = if self.is_tail {
            !self.is_spend && self.t == [false; 2] && self.slots[0] == 0 && self.slots[1] == 0
        } else {
            self.tail_t == [z; 2]
        };
        let ok_just = (self.t[0] || self.just_t[0] == z)
            && (self.t[1] || self.just_t[1] == z)
            && (self.j[0] || self.just_n[0] == z)
            && (self.j[1] || self.just_n[1] == z)
            && (!self.t[0] || self.slots[0] == 0)
            && (!self.t[1] || self.slots[1] == 0)
            && (!self.j[0] || self.slots[2] == 0)
            && (!self.j[1] || self.slots[3] == 0);
        ok_spend && ok_tail && ok_just
    }
}

/// Fill one row's extension at `ext` from the witness and the row's absorbed statement (`abs[ABS_*]`); returns the
/// PUBLISHED block, digest by digest — what the chain hashes and the wire carries.
#[must_use]
pub fn lay_slot_ledger_row(row: &mut [Fa4], ext: usize, abs: &[Digest; ABS_DIGESTS], w: &SlotLedgerWitness) -> [Digest; PUB_DIGESTS] {
    let b = |x: bool| f(u64::from(x));
    row[ext + SL_IS_SPEND] = b(w.is_spend);
    row[ext + SL_J0] = b(w.j[0]);
    row[ext + SL_J1] = b(w.j[1]);
    row[ext + SL_T0] = b(w.t[0]);
    row[ext + SL_T1] = b(w.t[1]);
    row[ext + SL_IS_TAIL] = b(w.is_tail);
    for c in 0..DIGEST_LANES {
        row[ext + SL_SEED + c] = f(w.seed[c]);
        row[ext + SL_TAIL_T0 + c] = f(w.tail_t[0][c]);
        row[ext + SL_TAIL_T1 + c] = f(w.tail_t[1][c]);
        row[ext + SL_JUST_T0 + c] = f(w.just_t[0][c]);
        row[ext + SL_JUST_T1 + c] = f(w.just_t[1][c]);
        row[ext + SL_JUST_N0 + c] = f(w.just_n[0][c]);
        row[ext + SL_JUST_N1 + c] = f(w.just_n[1][c]);
        row[ext + SL_COVER_D + c] = f(w.cover_d[c]);
    }
    row[ext + SL_SLOT_LC] = f(w.slot_lc);
    row[ext + SL_SLOT_T0] = f(w.slots[0]);
    row[ext + SL_SLOT_T1] = f(w.slots[1]);
    row[ext + SL_SLOT_N0] = f(w.slots[2]);
    row[ext + SL_SLOT_N1] = f(w.slots[3]);
    // the six blocks, laid from the same native derivations the door uses
    let lay = |row: &mut [Fa4], base: usize, l: Digest, r: Digest| {
        crate::pow_pq_air::lay_perm_row_flat(row, base, crate::pow_pq_air::pair_state(&l, &r));
    };
    lay(row, ext + SL_B_T0, lanes_of(&[COVER_NF_DOMAIN, w.slots[0]]), w.seed);
    lay(row, ext + SL_B_T1, lanes_of(&[COVER_NF_DOMAIN, w.slots[1]]), w.seed);
    lay(row, ext + SL_B_N0, lanes_of(&[COVER_CM_DOMAIN, w.slots[2]]), w.seed);
    lay(row, ext + SL_B_N1, lanes_of(&[COVER_CM_DOMAIN, w.slots[3]]), w.seed);
    lay(row, ext + SL_B_SEED, lanes_of(&[HEADER_SEED_DOMAIN]), w.seed);
    lay(row, ext + SL_B_LC, lanes_of(&[COVER_LC_DOMAIN, w.slot_lc]), w.seed);
    // the published block, by the SAME selection the laws state
    let out_of = |row: &[Fa4], blk: usize| -> Digest {
        use p3_field::PrimeField64;
        core::array::from_fn(|c| row[ext + blk + crate::pow_pq_air::PERM_OUT + c].as_canonical_u64())
    };
    let zero = [0u64; DIGEST_LANES];
    let tag0 = if w.is_spend { abs[ABS_NULLIFIER] } else if w.t[0] { w.just_t[0] } else if w.is_tail { w.tail_t[0] } else { out_of(row, SL_B_T0) };
    let tag1 = if w.is_spend { abs[ABS_TAG1] } else if w.t[1] { w.just_t[1] } else if w.is_tail { w.tail_t[1] } else { out_of(row, SL_B_T1) };
    let out0 = if w.is_spend { abs[ABS_OUT0] } else if w.j[0] { w.just_n[0] } else { out_of(row, SL_B_N0) };
    let out1 = if w.is_spend { abs[ABS_OUT1] } else if w.j[1] { w.just_n[1] } else { out_of(row, SL_B_N1) };
    let lc = if w.is_spend { abs[ABS_LC] } else { out_of(row, SL_B_LC) };
    let d = if w.is_spend { abs[ABS_D] } else { w.cover_d };
    let mut flags = zero;
    flags[0] = u64::from(w.j[0]);
    flags[1] = u64::from(w.j[1]);
    flags[2] = u64::from(w.t[0]);
    flags[3] = u64::from(w.t[1]);
    let published = [tag0, tag1, out0, out1, lc, d, flags, zero];
    for (k, dg) in published.iter().enumerate() {
        for c in 0..DIGEST_LANES {
            row[ext + SL_PUB + k * DIGEST_LANES + c] = f(dg[c]);
        }
    }
    published
}

/// The row's LAWS, as residuals — the in-circuit twin of [`lay_slot_ledger_row`]. `abs(k, c)` reads lane `c` of
/// absorbed digest `k` wherever the enclosing table holds it; `seed_commit` is the block's public seed commitment.
/// ⭐ V2 (a) (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16) — generic over the field its row lives in, the type parameter
/// NAMED `Ea4` so the body is the production body (lane agg's `gate_trace` pattern): the native instantiation is unchanged
/// code, and `gate_trace::Sym` traces these laws into the program the tree runs in circuit.
pub fn push_slot_ledger_laws<Ea4: p3_field::Algebra<Fa4> + Copy + 'static>(
    rs: &mut Vec<Ea4>,
    local: &Row<'_, Ea4>,
    ext: usize,
    abs: &dyn Fn(usize, usize) -> Ea4,
    seed_commit: &[Ea4; DIGEST_LANES],
) {
    let one = Ea4::ONE;
    let zero = Ea4::ZERO;
    let e = |v: u64| Ea4::from(f(v));
    let x = |off: usize| local[ext + off];
    let s = x(SL_IS_SPEND);
    let tl = x(SL_IS_TAIL);
    let (j0, j1, t0, t1) = (x(SL_J0), x(SL_J1), x(SL_T0), x(SL_T1));
    // B1. booleans
    for v in [s, j0, j1, t0, t1, tl] {
        rs.push(v * (v - one));
    }
    // B2. class exclusion: a spend row justifies nothing; a tail row (§18) is no spend row and justifies no tag
    rs.push(s * (j0 + j1 + t0 + t1));
    rs.push(s * tl);
    rs.push(tl * (t0 + t1));
    rs.push(tl * x(SL_SLOT_T0));
    rs.push(tl * x(SL_SLOT_T1));
    // B3. C1 — every witness a class does not use is forced to zero
    rs.push(s * x(SL_SLOT_T0));
    rs.push(s * x(SL_SLOT_T1)); // DB-329 §7e: a spend's tag1 is its carrier's claim, never a cover slot
    rs.push(s * x(SL_SLOT_N0));
    rs.push(s * x(SL_SLOT_N1));
    rs.push(t0 * x(SL_SLOT_T0));
    rs.push(t1 * x(SL_SLOT_T1));
    rs.push(j0 * x(SL_SLOT_N0));
    rs.push(j1 * x(SL_SLOT_N1));
    rs.push(s * x(SL_SLOT_LC));
    for c in 0..DIGEST_LANES {
        rs.push((one - t0) * x(SL_JUST_T0 + c));
        rs.push((one - t1) * x(SL_JUST_T1 + c));
        rs.push((one - j0) * x(SL_JUST_N0 + c));
        rs.push((one - j1) * x(SL_JUST_N1 + c));
        rs.push(s * x(SL_COVER_D + c));
        rs.push((one - tl) * x(SL_TAIL_T0 + c));
        rs.push((one - tl) * x(SL_TAIL_T1 + c));
    }
    // B4–B7. the five blocks: whole permutations, inputs welded, outputs read by B8 (never decorative)
    let out = crate::pow_pq_air::PERM_OUT;
    let weld = |rs: &mut Vec<Ea4>, blk: usize, left: &dyn Fn(usize) -> Ea4, right: &dyn Fn(usize) -> Ea4| {
        crate::pow_pq_air::push_perm_residuals(local, ext + blk, rs);
        for c in 0..DIGEST_LANES {
            rs.push(x(blk + c) - left(c));
            rs.push(x(blk + DIGEST_LANES + c) - right(c));
        }
    };
    let seed = |c: usize| x(SL_SEED + c);
    // seed commit: P(HEADER_SEED_DOMAIN ‖ 0…, seed) == the public commit
    weld(rs, SL_B_SEED, &|c| if c == 0 { e(HEADER_SEED_DOMAIN) } else { zero }, &seed);
    for c in 0..DIGEST_LANES {
        rs.push(x(SL_B_SEED + out + c) - seed_commit[c]);
    }
    // cover tags and notes: P(domain ‖ slot, seed)
    weld(rs, SL_B_T0, &|c| match c { 0 => e(COVER_NF_DOMAIN), 1 => x(SL_SLOT_T0), _ => zero }, &seed);
    weld(rs, SL_B_T1, &|c| match c { 0 => e(COVER_NF_DOMAIN), 1 => x(SL_SLOT_T1), _ => zero }, &seed);
    weld(rs, SL_B_N0, &|c| match c { 0 => e(COVER_CM_DOMAIN), 1 => x(SL_SLOT_N0), _ => zero }, &seed);
    weld(rs, SL_B_N1, &|c| match c { 0 => e(COVER_CM_DOMAIN), 1 => x(SL_SLOT_N1), _ => zero }, &seed);
    weld(rs, SL_B_LC, &|c| match c { 0 => e(COVER_LC_DOMAIN), 1 => x(SL_SLOT_LC), _ => zero }, &seed);
    // B8. the published block — ONE selector switches every cell of a spend's statement
    let pubc = |k: usize, c: usize| x(SL_PUB + k * DIGEST_LANES + c);
    for c in 0..DIGEST_LANES {
        let cover_t0 = x(SL_B_T0 + out + c);
        let cover_t1 = x(SL_B_T1 + out + c);
        let cover_n0 = x(SL_B_N0 + out + c);
        let cover_n1 = x(SL_B_N1 + out + c);
        // §18: a tail row's tag cell is its free tail witness (bound by the tag ledger's chain at the door)
        let tag_cell0 = tl * x(SL_TAIL_T0 + c) + (one - tl) * cover_t0;
        let tag_cell1 = tl * x(SL_TAIL_T1 + c) + (one - tl) * cover_t1;
        rs.push(pubc(PUB_TAG0, c) - (s * abs(ABS_NULLIFIER, c) + (one - s) * ((one - t0) * tag_cell0 + t0 * x(SL_JUST_T0 + c))));
        rs.push(pubc(PUB_TAG1, c) - (s * abs(ABS_TAG1, c) + (one - s) * ((one - t1) * tag_cell1 + t1 * x(SL_JUST_T1 + c))));
        rs.push(pubc(PUB_OUT0, c) - (s * abs(ABS_OUT0, c) + (one - s) * ((one - j0) * cover_n0 + j0 * x(SL_JUST_N0 + c))));
        rs.push(pubc(PUB_OUT1, c) - (s * abs(ABS_OUT1, c) + (one - s) * ((one - j1) * cover_n1 + j1 * x(SL_JUST_N1 + c))));
        rs.push(pubc(PUB_LC, c) - (s * abs(ABS_LC, c) + (one - s) * x(SL_B_LC + out + c)));
        rs.push(pubc(PUB_D, c) - (s * abs(ABS_D, c) + (one - s) * x(SL_COVER_D + c)));
        let flag = match c {
            0 => j0,
            1 => j1,
            2 => t0,
            3 => t1,
            _ => zero,
        };
        rs.push(pubc(PUB_FLAGS, c) - flag);
        rs.push(pubc(PUB_FLAGS + 1, c));
    }
}

/// The extension's own free columns (relative to `ext`): none. Every witness is read by a law — the seed by six
/// welds, the slots (and `slot_lc`) by their blocks' input welds, `cover_d` by B8 on a cover row (forced zero on a spend), the justified values by B8 (and forced to zero when their bit is
/// off), the published cells by B8. The aggregate declares the published block as bound by the chain tie exactly as it
/// declares today's tuple.
#[must_use]
pub fn slot_ledger_free_columns(_ext: usize) -> Vec<usize> {
    Vec::new()
}

/// The degree the laws add over the permutation: B8's `(1 − s)·(1 − t)·(1 − tail)·block_out` is degree 4 (§18 added
/// the tail selector), the permutation's own laws are `pow_pq_air::PERM_MAX_DEGREE`; in an aggregate the bound step's
/// closing equation dominates both.
#[must_use]
pub fn slot_ledger_law_degree() -> usize {
    crate::pow_pq_air::PERM_MAX_DEGREE.max(4)
}

// ── A STANDALONE gate over one row, for the RED-first pins and the strict censuses ─────────────────────────────────

/// One row: the five absorbed digests as plain witness columns at `0..ABS_DIGESTS·DIGEST_LANES`, then the extension.
pub const SG_ABS: usize = 0;
pub const SG_EXT: usize = ABS_DIGESTS * DIGEST_LANES;
pub const SG_COLS: usize = SG_EXT + SL_EXT_COLS;
/// The standalone table's height — a ROW is the statement here (one row, replicated to a legal power-of-two trace, as
/// `nf_sparse_air::ACC_FOLD_ROWS` does); the production list is `SLOT_LEDGER_ROWS` rows of the aggregate's step table.
const SG_ROWS: usize = 8;

/// The standalone gate's PUBLIC statement: the seed commitment and the published block (the aggregate binds the
/// published block through the chain digest instead; here it is a constant so a pin can name a tampered cell).
#[derive(Clone)]
pub struct SlotLedgerRowGate {
    pub seed_commit: [Ea4; DIGEST_LANES],
    pub published: [[Ea4; DIGEST_LANES]; PUB_DIGESTS],
}

impl AirConstraint for SlotLedgerRowGate {
    fn degree(&self, _nvars: usize) -> usize {
        slot_ledger_law_degree()
    }
    fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut rs: Vec<Ea4> = Vec::new();
        let abs = |k: usize, c: usize| local[SG_ABS + k * DIGEST_LANES + c];
        push_slot_ledger_laws(&mut rs, local, SG_EXT, &abs, &self.seed_commit);
        // the published block IS the public statement here
        for k in 0..PUB_DIGESTS {
            for c in 0..DIGEST_LANES {
                rs.push(local[SG_EXT + SL_PUB + k * DIGEST_LANES + c] - self.published[k][c]);
            }
        }
        let mut acc = Ea4::ZERO;
        for (i, r) in rs.into_iter().enumerate() {
            acc += e(i as u64 + 1) * r;
        }
        acc
    }
    /// The absorbed digests are witness columns here: on a spend row B8 reads them; on a cover row nothing does
    /// (they are a REPLICA of a real step in the aggregate, bound by its own ties). Named so the census reads the row
    /// under both selector values.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some((SG_ABS..SG_ABS + ABS_DIGESTS * DIGEST_LANES).collect())
    }
}

fn standalone_bind(seed_commit: Digest, published: &[Digest; PUB_DIGESTS]) -> Vec<Fa4> {
    let mut b = vec![f(COVER_NF_DOMAIN)];
    b.extend(seed_commit.iter().map(|v| f(*v)));
    for d in published {
        b.extend(d.iter().map(|v| f(*v)));
    }
    b
}

/// Prove ONE row standalone: returns the proof bytes and the published block. `None` for a witness that is not
/// well-formed (a producer bug, never a wire case).
#[must_use]
pub fn prove_slot_ledger_row_bytes(abs: &[Digest; ABS_DIGESTS], w: &SlotLedgerWitness) -> Option<(Vec<u8>, [Digest; PUB_DIGESTS])> {
    if !w.is_well_formed() {
        return None;
    }
    let mut row = vec![Fa4::ZERO; SG_COLS];
    for (k, d) in abs.iter().enumerate() {
        for c in 0..DIGEST_LANES {
            row[SG_ABS + k * DIGEST_LANES + c] = f(d[c]);
        }
    }
    let published = lay_slot_ledger_row(&mut row, SG_EXT, abs, w);
    let seed_commit = seed_commit_native(w.seed);
    let cols: Vec<Vec<Fa4>> = (0..SG_COLS).map(|c| vec![row[c]; SG_ROWS]).collect();
    let gate = SlotLedgerRowGate { seed_commit: e8(&seed_commit), published: core::array::from_fn(|k| e8(&published[k])) };
    let bytes = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
        cols,
        move |_g: Ea4| gate.clone(),
        &standalone_bind(seed_commit, &published),
    )?;
    Some((bytes, published))
}

/// Verify a standalone row against the public seed commitment and the published block it claims.
#[must_use]
pub fn verify_slot_ledger_row_bytes(bytes: &[u8], seed_commit: Digest, published: &[Digest; PUB_DIGESTS]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let gate = SlotLedgerRowGate { seed_commit: e8(&seed_commit), published: core::array::from_fn(|k| e8(&published[k])) };
    crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(
        bytes,
        move |_g: Ea4| gate.clone(),
        &standalone_bind(seed_commit, published),
        (SG_ROWS.trailing_zeros() as usize, SG_COLS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abs_fixture(i: u64) -> [Digest; ABS_DIGESTS] {
        core::array::from_fn(|k| lanes_of(&[0x5a5a, i, k as u64 + 1, 7]))
    }
    fn seed() -> Digest {
        lanes_of(&[0x5eed, 1, 2, 3])
    }

    /// CALIBRATION + the class table: a spend row publishes its absorbed statement, its tag1 the carrier's claim; a cover
    /// row publishes four cover cells and zero lc/D; a justified row publishes the door's note and tag with their bits.
    /// Every one proves and verifies.
    #[test]
    fn every_row_class_proves_verifies_and_publishes_exactly_what_its_class_says() {
        let abs = abs_fixture(1);
        let s = seed();
        let z = [0u64; DIGEST_LANES];
        // spend
        let w = SlotLedgerWitness::spend(s);
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &w).expect("a spend row proves");
        assert_eq!(p[PUB_TAG0], abs[ABS_NULLIFIER], "a spend row's tag0 is its nullifier");
        assert_eq!(p[PUB_TAG1], abs[ABS_TAG1], "its tag1 is its carrier's proven claim (DB-329 §7e)");
        assert_eq!((p[PUB_OUT0], p[PUB_OUT1], p[PUB_LC], p[PUB_D]), (abs[ABS_OUT0], abs[ABS_OUT1], abs[ABS_LC], abs[ABS_D]));
        assert_eq!(p[PUB_FLAGS], z, "a spend row justifies nothing");
        assert!(verify_slot_ledger_row_bytes(&bytes, seed_commit_native(s), &p), "the spend row verifies");
        // cover
        let w = SlotLedgerWitness::cover(s, [11, 12, 13, 14]);
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &w).expect("a cover row proves");
        assert_eq!(p[PUB_TAG0], cover_tag_native(s, 11));
        assert_eq!(p[PUB_TAG1], cover_tag_native(s, 12));
        assert_eq!(p[PUB_OUT0], cover_note_native(s, 13));
        assert_eq!(p[PUB_OUT1], cover_note_native(s, 14));
        assert_eq!((p[PUB_LC], p[PUB_D]), (cover_lc_native(s, 0), z), "a cover row publishes its cover cross-bind and its filing digest");
        let cd = lanes_of(&[0xfd, 5, 6, 7]);
        let w = SlotLedgerWitness { slot_lc: 15, cover_d: cd, ..SlotLedgerWitness::cover(s, [11, 12, 13, 14]) };
        let (bytes_lc, p_lc) = prove_slot_ledger_row_bytes(&abs, &w).expect("a cover row with its lc slot and D proves");
        assert_eq!((p_lc[PUB_LC], p_lc[PUB_D]), (cover_lc_native(s, 15), cd), "padding v2 §9: lc by the cover law, D the producer's filing digest");
        assert!(verify_slot_ledger_row_bytes(&bytes_lc, seed_commit_native(s), &p_lc));
        let mut off_law = p_lc;
        off_law[PUB_LC] = lanes_of(&[0x1c, 1, 1, 1]);
        assert!(!verify_slot_ledger_row_bytes(&bytes_lc, seed_commit_native(s), &off_law), "⛔ a cover lc off the law verified");
        assert!(verify_slot_ledger_row_bytes(&bytes, seed_commit_native(s), &p));
        // justified note + justified tag, on one cover row
        let jn = lanes_of(&[0x3a5, 1, 1, 1]);
        let jt = lanes_of(&[0x7a6, 2, 2, 2]);
        let w = SlotLedgerWitness { j: [true, false], t: [false, true], just_n: [jn, z], just_t: [z, jt], ..SlotLedgerWitness::cover(s, [21, 0, 0, 24]) };
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &w).expect("a justified row proves");
        assert_eq!(p[PUB_OUT0], jn, "the door's justified note rides the cell");
        assert_eq!(p[PUB_TAG1], jt, "the door's justified tag rides the cell");
        assert_eq!(p[PUB_FLAGS][..4], [1, 0, 0, 1], "the public bits say which cells the door must check");
        assert!(verify_slot_ledger_row_bytes(&bytes, seed_commit_native(s), &p));
    }

    /// ⛔ ALL-OR-NOTHING PER ROW (the consensus lane's pin, 02:25): a spend row cannot publish its nullifier without its
    /// outputs, nor another out beside its nullifier — the published block is a function of ONE selector.
    #[test]
    fn a_spend_row_publishing_a_cell_that_is_not_its_carriers_is_refused() {
        let abs = abs_fixture(2);
        let s = seed();
        let w = SlotLedgerWitness::spend(s);
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &w).expect("proves");
        let sc = seed_commit_native(s);
        assert!(verify_slot_ledger_row_bytes(&bytes, sc, &p), "CALIBRATION");
        let mut other_out = p;
        other_out[PUB_OUT0] = lanes_of(&[0xbad, 1, 2, 3]);
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &other_out), "⛔ a spend row published an out its carrier never proved");
        let mut no_out = p;
        no_out[PUB_OUT1] = [0; DIGEST_LANES];
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &no_out), "⛔ a spend row published its nullifier without an output");
        let mut other_tag = p;
        other_tag[PUB_TAG0] = lanes_of(&[0xdead, 1, 2, 3]);
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &other_tag), "⛔ a spend row published a tag that is not its nullifier");
        // DB-329 §7e: tag1 is the carrier's claim — a cover tag in its place (the pre-§7e shape) is refused too
        let mut cover_tag1 = p;
        cover_tag1[PUB_TAG1] = cover_tag_native(s, 3);
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &cover_tag1), "⛔ a spend row published a cover tag1 instead of its claim");
    }

    /// ⛔ DB-329 §7e — a spend row's published `tag1` IS its carrier's proven claim: a producer cannot publish another
    /// claim (another key's slot, a stranger's key) beside a carrier that proved this one, and cannot slip a cover slot
    /// under a spend row (C1 forces the spend row's tag1 slot to zero, so the row has no second spelling).
    /// TWO-PARTY-REVIEWED: this is the ROW's own accept/refuse verdict — the producer proves, the verifier sees only the
    /// published block and the seed commitment. The two-endpoint form (one producer's ledger, a peer verifying from the
    /// published list alone) is `settlement_delta::ledger_tests`; the claim's cross-spend collision lives with the spent
    /// SET at the node's door.
    #[test]
    fn db329_a_spend_row_publishing_a_claim_its_carrier_never_proved_is_refused() {
        let abs = abs_fixture(8);
        let s = seed();
        let sc = seed_commit_native(s);
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &SlotLedgerWitness::spend(s)).expect("proves");
        assert!(verify_slot_ledger_row_bytes(&bytes, sc, &p), "CALIBRATION: the honest claim verifies");
        let mut q = p;
        q[PUB_TAG1] = slot_claim_native(lanes_of(&[0x51, 0x07, 1, 2]), 1);
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &q), "⛔ a spend row published a claim its carrier never proved");
        let mut w = SlotLedgerWitness::spend(s);
        w.slots[1] = 5;
        assert!(!w.is_well_formed(), "a spend row with a cover tag1 slot");
        assert!(prove_slot_ledger_row_bytes(&abs, &w).is_none(), "the prover refuses it");
    }

    /// ⛔ H2's pin: a planted real-shaped tag in ANY cover tag cell — tag0 of a cover row, tag1 of every row — fails the
    /// cover law; so does a planted note in a cover note cell.
    #[test]
    fn db_padding_a_planted_real_shaped_tag_in_a_cover_cell_is_refused_by_the_cover_law() {
        let abs = abs_fixture(3);
        let s = seed();
        let sc = seed_commit_native(s);
        let planted = lanes_of(&[0x9999, 8, 8, 8]);
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &SlotLedgerWitness::cover(s, [1, 2, 3, 4])).expect("proves");
        for cell in [PUB_TAG0, PUB_TAG1, PUB_OUT0, PUB_OUT1] {
            let mut q = p;
            q[cell] = planted;
            assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &q), "⛔ a planted value in cover cell {cell} verified");
        }
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &SlotLedgerWitness::spend(s)).expect("proves");
        let mut q = p;
        q[PUB_TAG1] = planted;
        assert!(!verify_slot_ledger_row_bytes(&bytes, sc, &q), "⛔ a planted tag1 on a spend row verified");
    }

    /// C2: the seed is bound to the public commitment on every row — a row under another seed, or a commitment that is
    /// not this seed's, is refused.
    #[test]
    fn a_row_under_another_seed_or_another_commitment_is_refused() {
        let abs = abs_fixture(4);
        let s = seed();
        let (bytes, p) = prove_slot_ledger_row_bytes(&abs, &SlotLedgerWitness::cover(s, [1, 2, 3, 4])).expect("proves");
        assert!(verify_slot_ledger_row_bytes(&bytes, seed_commit_native(s), &p), "CALIBRATION");
        let other = lanes_of(&[0x0dd, 5, 5, 5]);
        assert!(!verify_slot_ledger_row_bytes(&bytes, seed_commit_native(other), &p), "⛔ another seed's commitment verified this row");
        assert!(!verify_slot_ledger_row_bytes(&bytes, other, &p), "⛔ a commitment that commits to nothing verified this row");
    }

    /// TWO-PARTY-REVIEWED: the spend-or-decoy carrier's own verdicts — the wallet proves, the node's `cover_ok` door
    /// verifies from the tag list alone (`verify_spend_or_decoy_bytes`, the function the door calls). The two-process
    /// form is the wallet's admission-proof pin against the node's real handler.
    #[test]
    fn db329_the_claim_rides_row_one_of_the_spend_or_decoy_list_as_a_real_row() {
        // DB-329 §7f carriage: the send's constant-width list is [nf, claim, decoy(bound, 2..W)], proven by the
        // spend-or-decoy carrier with the claim row witnessed as a REAL row over `slot_claim_preimage` — the gate's real
        // branch proves only `tag == P(a, b)`, and a claim is exactly that shape. CALIBRATION: the honest list proves and
        // verifies. REFUSALS: a claim row whose preimage is another key's does not prove (the prover cannot bluff its own
        // witness); the proof does not verify under a list whose row 1 names another claim; a list that keeps the row-1
        // DECOY (the pre-§7f shape) under a claim witness does not prove.
        use crate::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, verify_spend_or_decoy_bytes, TagWitness};
        use crate::nullifier_insert_air::poseidon_pair_native;
        let w: usize = 32; // PRODUCTION-SCALE-REVIEWED: the protocol's TX_FIXED_NULLIFIER_COUNT, the list every send settles
        let bound = lanes_of(&[0xb0, 0x0d, 1, 2]);
        let (sk, leaf) = (lanes_of(&[11, 12, 13, 14]), lanes_of(&[21, 22, 23, 24]));
        let nf = poseidon_pair_native(sk, leaf);
        let key = lanes_of(&[0x363, 5, 6, 7]);
        let claim = slot_claim_native(key, 0);
        let list = |row1: Digest| -> Vec<Digest> {
            let mut v = vec![nf, row1];
            v.extend((2..w as u64).map(|s| cover_tag_native(bound, s)));
            v
        };
        let wit = |pre: (Digest, Digest)| -> Vec<TagWitness> {
            let mut v = vec![TagWitness::RealSpend { key: sk, leaf }, TagWitness::RealSpend { key: pre.0, leaf: pre.1 }];
            v.extend((2..w).map(|_| TagWitness::Decoy));
            v
        };
        let honest = list(claim);
        let proof = prove_spend_or_decoy_bytes(bound, &honest, &wit(slot_claim_preimage(key, 0))).expect("the honest list proves");
        assert!(verify_spend_or_decoy_bytes(&proof, &honest), "CALIBRATION: the claim at row 1 verifies as a real row");
        assert!(
            prove_spend_or_decoy_bytes(bound, &honest, &wit(slot_claim_preimage(lanes_of(&[9, 9, 9, 9]), 0))).is_none(),
            "⛔ a claim row proved under another key's preimage"
        );
        let other = list(slot_claim_native(key, 1));
        assert!(!verify_spend_or_decoy_bytes(&proof, &other), "⛔ the proof verified under a list naming another claim at row 1");
        let pre_7f = list(cover_tag_native(bound, 1));
        assert!(
            prove_spend_or_decoy_bytes(bound, &pre_7f, &wit(slot_claim_preimage(key, 0))).is_none(),
            "⛔ a list keeping the row-1 decoy proved under a claim witness"
        );
    }

    /// The claim tag's native spelling (for the spender's carrier law): deterministic per `(slot_key, d)` and distinct
    /// across keys and slots — two devices of one seed collide, a stranger never does, and a claim never lands on a cover
    /// tag.
    #[test]
    fn a_slot_claim_collides_within_one_key_and_never_across_keys() {
        let k1 = lanes_of(&[1, 1, 1, 1]);
        let k2 = lanes_of(&[2, 2, 2, 2]);
        assert_eq!(slot_claim_native(k1, 4), slot_claim_native(k1, 4), "same key, same slot: ONE tag — the set arbitrates");
        assert_ne!(slot_claim_native(k1, 4), slot_claim_native(k1, 5), "another slot is another tag");
        assert_ne!(slot_claim_native(k1, 4), slot_claim_native(k2, 4), "another key is another tag: a stranger collides with nothing");
        assert_ne!(slot_claim_native(k1, 4), cover_tag_native(k1, 4), "a claim never lands on a cover tag (domains differ)");
    }

    /// C1 in the producer: a witness carrying a value its class does not use is refused before any proof work.
    #[test]
    fn a_witness_with_an_unused_value_is_not_well_formed() {
        let s = seed();
        let mut w = SlotLedgerWitness::spend(s);
        w.slots[2] = 9;
        assert!(!w.is_well_formed(), "a spend row with a cover note slot");
        let mut w = SlotLedgerWitness::cover(s, [1, 2, 3, 4]);
        w.just_n[0] = lanes_of(&[1, 2, 3, 4]);
        assert!(!w.is_well_formed(), "a justified value without its bit");
        let mut w = SlotLedgerWitness::spend(s);
        w.t[0] = true;
        assert!(!w.is_well_formed(), "a spend row claiming a justified tag");
        let mut w2 = SlotLedgerWitness::spend(s);
        w2.slot_lc = 3;
        assert!(!w2.is_well_formed(), "a spend row with a cover lc slot");
        let mut w2 = SlotLedgerWitness::spend(s);
        w2.cover_d = lanes_of(&[1, 1, 1, 1]);
        assert!(!w2.is_well_formed(), "a spend row with a cover filing digest");
        assert!(prove_slot_ledger_row_bytes(&abs_fixture(5), &w).is_none(), "the prover refuses it");
    }

    /// Nothing of a cover row's published block depends on the absorbed statement beside it (§2.6: the replica is
    /// tied, the publication is not).
    #[test]
    fn a_cover_rows_published_block_is_independent_of_the_absorbed_statement() {
        let s = seed();
        let w = SlotLedgerWitness::cover(s, [1, 2, 3, 4]);
        let mut r1 = vec![Fa4::ZERO; SG_COLS];
        let mut r2 = vec![Fa4::ZERO; SG_COLS];
        let p1 = lay_slot_ledger_row(&mut r1, SG_EXT, &abs_fixture(6), &w);
        let p2 = lay_slot_ledger_row(&mut r2, SG_EXT, &abs_fixture(7), &w);
        assert_eq!(p1, p2, "two different absorbed statements, one published block");
    }
}

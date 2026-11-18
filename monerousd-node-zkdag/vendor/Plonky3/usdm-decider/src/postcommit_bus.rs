// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ A-F57 (2026-11-15, lane af57) — THE DSOL CALL PROOF'S ENGINE, BOUND, HIDING AND BALANCED BY CONSTRUCTION.
//!
//! # What was broken, measured
//!
//! This engine proves a DSOL contract call (`dsol_cpu_air::verify_dsol_call`, its only production caller). Until
//! 2026-11-15 it finished with two masked sumchecks (`p3_whir::pcs::hiding::prove_hvzk` / `verify_hvzk`).
//!
//! **The opened row bound nothing.**
//! - `verify_hvzk` drops the sumcheck's final target (`whir/src/pcs/hiding.rs:121`), and no commitment of the witness
//!   was ever opened against a claim.
//! - So every value the carrier sent verified as whatever it said.
//! - MEASURED (`dsol_cpu_air::fetch_tests::af55_…`, run with a well-formed forge): a call proof whose CPU opened row was
//!   SOLVED for a `storage_post` the run never reached verified at the door, 95,908 B.
//!
//! **Four more defects, read in the same code.**
//! - A bus side's column-sum `opened` was never claimed.
//! - The CPU gate's next-row values were only absorbed, never bound.
//! - A `Free` side's counts were laid after α and tied to nothing, so four ROM rows' counts balanced a fetch the program
//!   lacks.
//! - The side table's `idx` column entered every bus key, and no tie or law held it.
//!
//! **And a privacy leak (A-F72).** Each side's LogUp total rode the carrier in the clear while the ROM is public, so
//! the per-instruction counts were four linear equations, with more from the column-sum rounds.
//!
//! # The engine now (spec: docs/AF57-POSTCOMMIT-BUS-BINDING-SPEC-20261115.md)
//!
//! ```text
//! ROUND 1  each constraint table, with a Free side's derived counts APPENDED as a column (committed BEFORE α),
//!          BLINDED (§BE-1: the caller's rows, then as many rows of OS randomness), COMMITTED (light_commit: the
//!          Merkle root and the OOD answers, observed)
//!          ↓
//!          draw α, β                                                ← a function of the committed trace
//!          ↓
//! ROUND 2  ONE bus table per bus: each side's key columns and multiplicity (copies of its source's rows), the
//!          LogUp term h = mult/(α − Σ β^(i+1)·val_i) per side, and ONE running sum acc (0 → 0) — blinded, committed
//!          ↓
//!          draw r*                                                  ← after BOTH commitments
//!          ↓
//!          every side's key and multiplicity columns opened at r* in the bus table and in its source, and equal
//!          ↓
//!          draw γ; every table's zerocheck under its gate (wrapped in [`BlindedRows`]), its row claimed on its
//!          commitment, its next-row values bound by the shift bind; the bus tables likewise (the running sum's laws)
//!          ↓
//!          two WHIR openings, one per commitment, discharging every claim
//! ```
//!
//! BORROWED, each with its source:
//! - the commitment and the opening: DB-452's `light_commit`, the PCS every block proof opens under;
//! - the blinding and its selector: committed_air's §BE-1 door;
//! - the next-row binding: the HyperPlonk / Jolt shift reduction (`light_commit::prove_shift_bind`), in the bound
//!   engine's exact order (`whir_rec_block.rs`, the light batch);
//! - the running sum: Plonky3's LogUp (`p3-lookup`);
//! - the multiplicities before the challenge: standard LogUp (Haböck 2022).
//!
//! # DB-159 and H6 — why the challenges come where they do (unchanged by A-F57)
//!
//! **α after the trace.** LogUp is a rational-identity argument: `Σ mult_i/(α − key_i) == 0` certifies a multiset
//! equality only when `α` is random GIVEN the multisets. So `α` and `β` are drawn after round 1 is committed (DB-159:
//! they were once drawn from the statement alone).
//!
//! **r* after both rounds.** `r*` is drawn after BOTH commitments, so neither side can be crafted to agree with the other
//! only at a point it knew.
//!
//! **Who fixes the multiplicities (H6).**
//! - A [`BusMult::Column`] side's multiplicity IS a round-1 column its source AIR constrains (a `real` flag).
//! - A [`BusMult::Free`] side's is DERIVED by the prover from the `Column` sides' keys ([`derive_side_multiplicities`])
//!   and committed with round 1, so it is fixed before α (A-F57 defect 4).
//! - Every side's multiplicity copy is tied to its source at `r*`.
//! - A bus needs at least one `Column` side and admits at most one `Free` side ([`spec_admissible`]).
//!
//! # Hiding
//!
//! Every table is doubled and its second half is fresh OS randomness ([`crate::committed_air::blind_cols`]). Every gate
//! holds on the first half only (the `1 − x[0]` selector of [`BlindedRows`]). So every value the carrier sends — an
//! opened row, a next-row value, a tie, a WHIR answer — mixes random rows.
//!
//! The bus sends no per-side total and runs no column-sum sumcheck: the running sum's boundary laws (`acc = 0` first,
//! `acc + Σ h = 0` last) are zerocheck laws like any other. So nothing about how often an instruction ran leaves the
//! carrier (A-F72, H3).
//!
//! # Cost, scale and the NO-GROWTH bound
//!
//! - **Cost:** two Merkle commitments and two WHIR openings; one bus table per bus; a shift bind per row-shifted table;
//!   every table twice its laid height. Measured at the landing by the af57 pin (bytes, ms).
//! - **Bounds:** every collection is bounded by a named constant checked BEFORE anything is committed or allocated from a
//!   remote shape: [`BUS_MAX_TABLES`], [`BUS_MAX_BUSES`], [`BUS_MAX_SIDES`], [`BUS_MAX_KEY_COLS`], [`BUS_MAX_NVARS`],
//!   [`BUS_MAX_TABLE_WIDTH`], and the PCS's arity (`light_commit::light_arity_admissible`).
//! - **Scale:** nothing has a term in chain height, blocks, notes, spends, peers or bonded nodes. A verifying node
//!   persists none of it.
//! - **AI resistance:** (a), a proof every node checks.

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_multilinear_util::point::Point;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::air_zerocheck::{
    compact_shifted, prove_air_zerocheck, shifted_set, verify_air_zerocheck_over, AirConstraint, AirZerocheckProof, Row,
};
use crate::hiding_decider::{Chl, Ea4, Fa4, Perm16};
use crate::light_commit::{
    prove_shift_bind, verify_shift_bind, LightCommitProver, LightCommitVerifier, LightRound, ShiftBindProof,
};
use crate::poseidon2_compress::DIGEST_LANES;
use crate::whir_rec_block::{absorb_shifted_openings, draw_bus_fold_challenge, EXT_D, REC_DECIDER_SEED};

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The bounds. Every one is CHECKED in the shape gate — a named constant nothing enforces is just a
// sentence, and a remote sender's declared shape must never become an allocation.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The most constraint tables one carrier commits in a round.
pub const BUS_MAX_TABLES: usize = 64;
/// The most buses one carrier may declare — the validator finality certificate's five is the widest use
/// in this tree.
pub const BUS_MAX_BUSES: usize = 16;
/// Sides per bus. A bus has at most one side per table, so it inherits the table bound.
pub const BUS_MAX_SIDES: usize = BUS_MAX_TABLES;
/// The widest key tuple a bus folds: the `PK_D` bus's `pk_d ‖ rho`, two digests. DERIVED from the digest
/// width, so a wider digest moves it rather than silently truncating a key.
pub const BUS_MAX_KEY_COLS: usize = 2 * DIGEST_LANES;
/// The tallest LAID table this carrier decodes, as a variable count (blinding adds one). `2^24` rows is past any call
/// this machine admits ([`crate::dsol_vm::STEP_BUDGET_MAX`] is `2^20`).
pub const BUS_MAX_NVARS: usize = 24;
/// The widest carrier table this verifier will decode — the protocol's own widest carrier, named rather
/// than restated.
pub const BUS_MAX_TABLE_WIDTH: usize = crate::whir_rec_block::AIR_DIRECT_MAX_WIDTH;

/// Where a bus side's per-row multiplicity comes from. ⛔ H6 (module header): a multiplicity nobody but the
/// prover fixes makes the bus vacuous, so there is no variant for "the caller hands in a vector".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusMult {
    /// The multiplicity is THIS round-1 column of the side's source table — copied into the bus table and
    /// tied at `r*` with the keys, so it is exactly what the source table's AIR constrained (typically a
    /// `real`-row flag: `1` on a row the trace occupies, `0` on padding). The only shape for a side whose
    /// every real row MUST be counted (the lookup / SEND side).
    Column(usize),
    /// Derived by the prover from the `Column` sides: `−Σ` of the signed multiplicities of every `Column`-side
    /// row whose key equals this row's key ([`derive_side_multiplicities`]). The standard LogUp TABLE side.
    /// A-F57: the counts are APPENDED to the source table as a round-1 column, committed before α and tied at `r*`
    /// like a `Column` side; they never leave the carrier. At most one per bus.
    Free,
}

/// One side of a bus: the table it reads, the columns whose tuple is the bus key, and where this side's
/// multiplicity per row comes from. The bus balances iff, over all sides, `Σ mult/(α − key)` is zero — i.e.
/// iff the `Column` sides' keyed multiset is exactly what the `Free` side receives.
#[derive(Clone, Debug)]
pub struct BusSide {
    /// Index into the round-1 tables of the table this side reads.
    pub table: usize,
    /// The source columns, in key order; their tuple is folded with `β` into one bus key. Bounded by
    /// [`BUS_MAX_KEY_COLS`], refused past it.
    pub cols: Vec<usize>,
    /// This side's multiplicity source. See [`BusMult`].
    pub mult: BusMult,
}

/// A bus: two or more sides whose multisets must agree. Bounded by [`BUS_MAX_SIDES`].
#[derive(Clone, Debug)]
pub struct BusSpec {
    pub sides: Vec<BusSide>,
}

/// Every side's multiplicity vector, resolved from the round-1 tables: a `Column` side's is its source
/// column; a `Free` side's is derived — for each of its rows, minus the sum of the signed multiplicities of
/// every `Column`-side row of the same bus whose key tuple equals this row's. When several `Free` rows share
/// a key the first receives the whole count and the rest zero; either distribution balances the same sum.
///
/// `None` when a `Column`-side row with a non-zero multiplicity has NO row of the `Free` side to land on:
/// that is a lookup of a key the table does not hold — the very thing the bus exists to refuse — and the
/// honest prover refuses it here, by name, instead of committing a sum that cannot balance.
///
/// Key tuples are compared as canonical integers, so two rows agree here iff they agree as field elements.
fn derive_side_multiplicities(spec: &BusSpec, tables1: &[Vec<Vec<Fa4>>]) -> Option<Vec<Vec<Fa4>>> {
    use std::collections::HashMap;
    let key_of = |t: &[Vec<Fa4>], cols: &[usize], r: usize| -> Option<Vec<u64>> {
        cols.iter().map(|&c| t.get(c).and_then(|col| col.get(r)).map(|v| v.as_canonical_u64())).collect()
    };
    let mut out: Vec<Vec<Fa4>> = Vec::with_capacity(spec.sides.len());
    for side in &spec.sides {
        let src = tables1.get(side.table)?;
        let h = src.first()?.len();
        out.push(match side.mult {
            BusMult::Column(c) => {
                let col = src.get(c)?;
                if col.len() != h {
                    return None;
                }
                col.clone()
            }
            BusMult::Free => vec![Fa4::ZERO; h],
        });
    }
    let Some(free) = spec.sides.iter().position(|s| s.mult == BusMult::Free) else { return Some(out) };
    let free_src = tables1.get(spec.sides[free].table)?;
    let free_h = free_src.first()?.len();
    let mut first_row: HashMap<Vec<u64>, usize> = HashMap::with_capacity(free_h);
    for r in 0..free_h {
        first_row.entry(key_of(free_src, &spec.sides[free].cols, r)?).or_insert(r);
    }
    for (k, side) in spec.sides.iter().enumerate() {
        if k == free {
            continue;
        }
        let src = tables1.get(side.table)?;
        for r in 0..out[k].len() {
            let m = out[k][r];
            if m == Fa4::ZERO {
                continue;
            }
            let j = *first_row.get(&key_of(src, &side.cols, r)?)?; // a lookup the table does not hold: refused
            out[free][j] -= m;
        }
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The wire.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// One side's tie at `r*`: its key and multiplicity columns opened in its SOURCE table (at the source's projection of
/// `r*`) and in the BUS table (at `r*`). Verify requires `bus = Π_(k=1..d)(1 − r*_k) · src`, column for column
/// ([`project`]).
#[derive(Clone, Serialize, Deserialize)]
pub struct TieProof {
    pub src: Vec<Ea4>,
    pub bus: Vec<Ea4>,
}

/// One proven bus: its challenges (drawn after round 1 is committed; verify re-derives and binds them) and each side's
/// tie. Nothing about any side's total rides here (A-F72): the running sum's boundary laws are the bus's verdict.
#[derive(Clone, Serialize, Deserialize)]
pub struct BusProof {
    pub alpha: Ea4,
    pub beta: Fa4,
    /// One per side, in the spec's order. Bounded by [`BUS_MAX_SIDES`].
    pub ties: Vec<TieProof>,
}

/// One committed round: the LAID shapes the statement fixes (blinding and appended columns are derived from them, never
/// sent), each table's zerocheck, each row-shifted table's shift bind, and the WHIR opening of the round's commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct RoundBundle {
    pub shapes: Vec<(usize, usize)>,
    /// One per table. Its `shifted_opened` is the gate's public next-row set alone (C2).
    pub zcs: Vec<AirZerocheckProof>,
    /// One per table: `Some` exactly when the table's gate reads the next row.
    pub binds: Vec<Option<ShiftBindProof>>,
    pub light: LightRound,
}

/// The whole two-round carrier.
#[derive(Clone, Serialize, Deserialize)]
pub struct PostCommitBusBundle {
    /// The constraint tables (with any `Free` side's counts), committed FIRST.
    pub round1: RoundBundle,
    /// The bus tables, committed AFTER `α`.
    pub round2: RoundBundle,
    /// Bounded by [`BUS_MAX_BUSES`].
    pub buses: Vec<BusProof>,
}

/// The `(nvars, width)` of a LAID table, or `None` when it is not a shape this verifier decodes.
fn shape_of(cols: &[Vec<Fa4>]) -> Option<(usize, usize)> {
    let width = cols.len();
    let h = cols.first().map(|c| c.len())?;
    if width == 0 || width > BUS_MAX_TABLE_WIDTH || h == 0 || !h.is_power_of_two() {
        return None;
    }
    let nv = h.trailing_zeros() as usize;
    if nv > BUS_MAX_NVARS || cols.iter().any(|c| c.len() != h) {
        return None;
    }
    Some((nv, width))
}

/// Refuse a spec this carrier cannot describe, BEFORE anything is committed or allocated.
fn spec_admissible(buses: &[BusSpec], shapes1: &[(usize, usize)]) -> bool {
    if buses.is_empty() || buses.len() > BUS_MAX_BUSES {
        return false;
    }
    for spec in buses {
        // A one-sided bus balances only against itself and proves nothing.
        if spec.sides.len() < 2 || spec.sides.len() > BUS_MAX_SIDES {
            return false;
        }
        for s in &spec.sides {
            if s.table >= shapes1.len() || s.cols.is_empty() || s.cols.len() > BUS_MAX_KEY_COLS {
                return false;
            }
            if s.cols.iter().any(|&c| c >= shapes1[s.table].1) {
                return false;
            }
            if shapes1[s.table].0 > BUS_MAX_NVARS {
                return false;
            }
            if let BusMult::Column(c) = s.mult {
                if c >= shapes1[s.table].1 {
                    return false;
                }
            }
        }
        // ⛔ H6: at least one side's multiplicities are a constrained source column, and at most one side's are
        // the prover's to derive — otherwise the bus is a sum the prover balances by choosing its own terms.
        let free = spec.sides.iter().filter(|s| s.mult == BusMult::Free).count();
        if free > 1 || free == spec.sides.len() {
            return false;
        }
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The plan: ONE derivation of every committed shape, every appended column and every bus table's layout from the LAID
// shapes and the public spec, read by the prover and the verifier alike.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Where one side sits in its bus table: `n_val` key columns from `val_base`, the multiplicity at `mult_col`, the four
/// limbs of `h` from `h_base`; `src_nvars` is its source table's LAID arity.
#[derive(Clone, Debug)]
struct SideCols {
    val_base: usize,
    n_val: usize,
    mult_col: usize,
    h_base: usize,
    src_nvars: usize,
}

/// A bus table: its sides, the running sum's four limbs from `acc_base`, its width, and its LAID arity (the tallest
/// side's).
#[derive(Clone, Debug)]
struct BusLayout {
    sides: Vec<SideCols>,
    acc_base: usize,
    width: usize,
    nvars: usize,
}

fn bus_layout(spec: &BusSpec, laid1: &[(usize, usize)]) -> Option<BusLayout> {
    let mut col = 0usize;
    let mut nvars = 0usize;
    let mut sides = Vec::with_capacity(spec.sides.len());
    for s in &spec.sides {
        let src_nvars = laid1.get(s.table)?.0;
        nvars = nvars.max(src_nvars);
        let n_val = s.cols.len();
        sides.push(SideCols { val_base: col, n_val, mult_col: col + n_val, h_base: col + n_val + 1, src_nvars });
        col += n_val + 1 + EXT_D;
    }
    let width = col + EXT_D;
    if width > BUS_MAX_TABLE_WIDTH {
        return None;
    }
    Some(BusLayout { sides, acc_base: col, width, nvars })
}

struct BusPlan {
    /// Per bus, per side: the column of its SOURCE table its multiplicity is (a `Free` side's appended column).
    mult_cols: Vec<Vec<usize>>,
    /// Per round-1 table: the columns this engine appended (a `Free` side's counts), in order.
    appended: Vec<Vec<usize>>,
    layouts: Vec<BusLayout>,
    committed1: Vec<(usize, usize)>,
    laid2: Vec<(usize, usize)>,
    committed2: Vec<(usize, usize)>,
}

impl BusPlan {
    /// `None` when the spec does not describe these shapes. The caller has run [`spec_admissible`].
    fn of(buses: &[BusSpec], laid1: &[(usize, usize)]) -> Option<Self> {
        let mut width: Vec<usize> = laid1.iter().map(|s| s.1).collect();
        let mut appended = vec![Vec::new(); laid1.len()];
        let mut mult_cols = Vec::with_capacity(buses.len());
        let mut layouts = Vec::with_capacity(buses.len());
        for spec in buses {
            let mut per = Vec::with_capacity(spec.sides.len());
            for s in &spec.sides {
                let w = width.get_mut(s.table)?;
                per.push(match s.mult {
                    BusMult::Column(c) => c,
                    BusMult::Free => {
                        let c = *w;
                        *w += 1;
                        appended[s.table].push(c);
                        c
                    }
                });
            }
            mult_cols.push(per);
            layouts.push(bus_layout(spec, laid1)?);
        }
        if width.iter().any(|&w| w > BUS_MAX_TABLE_WIDTH) {
            return None;
        }
        let committed1 = laid1.iter().zip(&width).map(|(&(nv, _), &w)| (nv + 1, w)).collect();
        let laid2: Vec<(usize, usize)> = layouts.iter().map(|l| (l.nvars, l.width)).collect();
        let committed2 = laid2.iter().map(|&(nv, w)| (nv + 1, w)).collect();
        Some(Self { mult_cols, appended, layouts, committed1, laid2, committed2 })
    }
}

/// The round-2 (bus table) LAID shapes a carrier MUST declare for these round-1 laid shapes and this spec: one table per
/// bus. `None` when the spec does not describe the shapes. The statement's shape function (`dsol_table_shapes`) reads
/// this, so prover, verifier and statement hold one derivation.
#[must_use]
pub fn bus_table_shapes(laid1: &[(usize, usize)], buses: &[BusSpec]) -> Option<Vec<(usize, usize)>> {
    if !spec_admissible(buses, laid1) {
        return None;
    }
    BusPlan::of(buses, laid1).map(|p| p.laid2)
}

/// THE ONE place a side's tied columns are derived, for the prover and the verifier alike: `(source columns, bus-table
/// columns)` — the keys and the multiplicity, every side, `Column` and `Free` alike (A-F57 defect 4).
fn tie_cols(side: &BusSide, mult_col: usize, sc: &SideCols) -> (Vec<usize>, Vec<usize>) {
    let mut src = side.cols.clone();
    src.push(mult_col);
    let mut bus: Vec<usize> = (sc.val_base..sc.val_base + sc.n_val).collect();
    bus.push(sc.mult_col);
    (src, bus)
}

/// A side's source point and scale for the bus table's point `p` (MSB first, `p[0]` the blinding selector): a source of
/// laid arity `c` sits in the bus table's first `2^c` rows of each half, zero above, so with `d = M − c` its columns are
/// `S(x) = C(x_0, x_(d+1..)) · Π_(k=1..d) (1 − x_k)`.
fn project(p: &[Ea4], src_nvars: usize) -> (Vec<Ea4>, Ea4) {
    let m = p.len() - 1;
    let d = m - src_nvars;
    let mut q = Vec::with_capacity(src_nvars + 1);
    q.push(p[0]);
    q.extend_from_slice(&p[1 + d..]);
    let scale = p[1..1 + d].iter().fold(Ea4::ONE, |a, &x| a * (Ea4::ONE - x));
    (q, scale)
}

fn limbs(e: Ea4) -> [Fa4; EXT_D] {
    let s = <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(&e);
    std::array::from_fn(|k| s[k])
}

fn basis(k: usize) -> Ea4 {
    Ea4::from_basis_coefficients_fn(|t| if t == k { Fa4::ONE } else { Fa4::ZERO })
}

fn random_fa4(rng: &mut SmallRng) -> Fa4 {
    Fa4::from_u64(u64::from(rng.random::<u32>()))
}

/// Build one bus table from the BLINDED round-1 tables. Each side's key and multiplicity columns are its source's rows —
/// data rows in the data half, blinding rows in the blinding half, zero above the source's height in each half — and its
/// `h` limbs are `mult/(α − key)` on the data half and fresh randomness on the blinding half; the running sum is
/// `acc[0] = 0`, `acc[i+1] = acc[i] + Σ_sides h[i]` on the data half and randomness on the blinding half. An unbalanced
/// bus is still laid: its last-row law refuses it (the verdict is the verifier's). `None` when α lands on a committed
/// key (a `1/|Ea4|` accident, refused rather than skipped).
#[allow(clippy::too_many_arguments)]
fn bus_table(
    blinded1: &[Vec<Vec<Fa4>>],
    spec: &BusSpec,
    mult_cols: &[usize],
    lay: &BusLayout,
    alpha: Ea4,
    beta: Fa4,
    rng: &mut SmallRng,
) -> Option<Vec<Vec<Fa4>>> {
    let half = 1usize << lay.nvars;
    let mut cols = vec![vec![Fa4::ZERO; 2 * half]; lay.width];
    let mut hsum = vec![Ea4::ZERO; half];
    for (k, side) in spec.sides.iter().enumerate() {
        let sc = &lay.sides[k];
        let src = blinded1.get(side.table)?;
        let sh = 1usize << sc.src_nvars;
        let mut copy = |dst: usize, c: usize| -> Option<()> {
            let s = src.get(c)?;
            if s.len() != 2 * sh {
                return None;
            }
            cols[dst][..sh].copy_from_slice(&s[..sh]);
            cols[dst][half..half + sh].copy_from_slice(&s[sh..]);
            Some(())
        };
        for (j, &c) in side.cols.iter().enumerate() {
            copy(sc.val_base + j, c)?;
        }
        copy(sc.mult_col, *mult_cols.get(k)?)?;
        for i in 0..half {
            let mut key = Ea4::ZERO;
            let mut bp = Ea4::from(beta);
            for j in 0..sc.n_val {
                key += bp * Ea4::from(cols[sc.val_base + j][i]);
                bp *= Ea4::from(beta);
            }
            let d = alpha - key;
            if d == Ea4::ZERO {
                return None;
            }
            let hv = Ea4::from(cols[sc.mult_col][i]) * d.inverse();
            hsum[i] += hv;
            for (l, v) in limbs(hv).into_iter().enumerate() {
                cols[sc.h_base + l][i] = v;
                cols[sc.h_base + l][half + i] = random_fa4(rng);
            }
        }
    }
    let mut acc = Ea4::ZERO;
    for (i, &hs) in hsum.iter().enumerate() {
        for (l, v) in limbs(acc).into_iter().enumerate() {
            cols[lay.acc_base + l][i] = v;
            cols[lay.acc_base + l][half + i] = random_fa4(rng);
        }
        acc += hs;
    }
    Some(cols)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The gates.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ⭐ A-F57 — §BE-1's BLINDING SELECTOR, WITH THE INNER GATE SCORED ON ITS OWN (LAID) POINT.
///
/// **What it does.** As `committed_air::Blinded`: the caller's rows are the first half, fresh randomness the second, and
/// the residual is multiplied by `1 − x[0]`, so it holds on the data half only. Then the inner gate is handed `x[1..]`, the
/// point of the LAID table.
///
/// **Why the laid point.** A gate that masks its first or last row (`is_first` / `is_last` as products over its point)
/// then masks the first and last DATA rows, with no change to the gate. The rotation the zerocheck reads runs over the
/// whole doubled table, so the last data row's "next" is a blinding row. The inner gate's own last-row mask keeps every
/// next-row law off it: the contract `member_path_gate` and A-F55's blob gate meet by reading `x[1..]`, held here at one
/// site.
///
/// **The selector is not a committed column.** `x[0]` is the zerocheck's own point, which the verifier holds, so there is
/// nothing for a prover to set to zero.
///
/// **Appended columns.** `appended` names the columns this engine added (a `Free` side's counts). They are bound by the
/// bus tie, and no gate reads them, so they are declared free.
#[derive(Clone)]
pub struct BlindedRows<C> {
    pub inner: C,
    pub appended: Vec<usize>,
}

impl<C: AirConstraint + Sync> AirConstraint for BlindedRows<C> {
    fn degree(&self, nvars: usize) -> usize {
        // one more than the inner gate's at its laid arity: the selector is linear in the point
        self.inner.degree(nvars.saturating_sub(1)) + 1
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let Some((&x0, data)) = x.split_first() else { return Ea4::ONE };
        (Ea4::ONE - x0) * self.inner.eval(local, at, data)
    }
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let Some((&x0, data)) = x.split_first() else { return vec![Ea4::ONE] };
        let sel = Ea4::ONE - x0;
        self.inner.residuals(local, at, data).into_iter().map(|r| sel * r).collect()
    }
    fn has_base_eval(&self) -> bool {
        self.inner.has_base_eval()
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let Some((&x0, data)) = x.split_first() else { return Ea4::ONE };
        self.inner.eval_base(local, at, data) * (Fa4::ONE - x0)
    }
    fn is_row_local(&self) -> bool {
        self.inner.is_row_local()
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        self.inner.shifted_cols()
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        if self.appended.is_empty() {
            return self.inner.free_columns();
        }
        let mut v = self.inner.free_columns().unwrap_or_default();
        v.extend(self.appended.iter().copied());
        v.sort_unstable();
        v.dedup();
        Some(v)
    }
}

/// ⭐ A-F57 — THE BUS TABLE'S LAWS (BORROWED: Plonky3's LogUp running sum, `p3-lookup`), on the laid point. For every
/// side, `h·(α − Σ_i β^(i+1)·val_i) − mult = 0` (the key has NO free term: every column of it is tied to the source, so
/// A-F57 defect 5 has no column to live in); and the running sum: `acc = 0` on the first data row, `acc' = acc + Σ h`
/// across every data transition, `acc + Σ h = 0` on the last data row. The bus balances iff all hold; no total is sent.
/// Degree 2 (a product of two row values; a mask times a row value); γ-batched.
#[derive(Clone)]
struct BusRun {
    alpha: Ea4,
    beta: Fa4,
    gamma: Ea4,
    /// `(val_base, n_val, mult_col, h_base)` per side.
    sides: Vec<(usize, usize, usize, usize)>,
    acc_base: usize,
}

fn bus_run(lay: &BusLayout, (alpha, beta): (Ea4, Fa4), gamma: Ea4) -> BusRun {
    BusRun {
        alpha,
        beta,
        gamma,
        sides: lay.sides.iter().map(|s| (s.val_base, s.n_val, s.mult_col, s.h_base)).collect(),
        acc_base: lay.acc_base,
    }
}

impl AirConstraint for BusRun {
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn is_row_local(&self) -> bool {
        false
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some((self.acc_base..self.acc_base + EXT_D).collect())
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let ext_row = |base: usize| (0..EXT_D).fold(Ea4::ZERO, |a, l| a + local[base + l] * basis(l));
        let mut acc_v = Ea4::ZERO;
        let g = self.gamma;
        let mut push = |r: Ea4| acc_v = acc_v * g + r;
        let mut hsum = Ea4::ZERO;
        for &(vb, n, m, hb) in &self.sides {
            let h = ext_row(hb);
            let mut key = Ea4::ZERO;
            let mut bp = Ea4::from(self.beta);
            for j in 0..n {
                key += bp * local[vb + j];
                bp *= Ea4::from(self.beta);
            }
            push(h * (self.alpha - key) - local[m]);
            hsum += h;
        }
        let acc = ext_row(self.acc_base);
        let nxt = (0..EXT_D).fold(Ea4::ZERO, |a, l| a + at(self.acc_base + l, &[]) * basis(l));
        let (mut first, mut last) = (Ea4::ONE, Ea4::ONE);
        for &xk in x {
            first *= Ea4::ONE - xk;
            last *= xk;
        }
        push(first * acc);
        push((Ea4::ONE - last) * (nxt - acc - hsum));
        push(last * (acc + hsum));
        acc_v
    }
}

/// The pinned challenger both sides rebuild from the seed, having observed the statement.
fn challenger(public_bind: &[Fa4]) -> Chl {
    let mut perm_rng = SmallRng::seed_from_u64(REC_DECIDER_SEED);
    let perm = Perm16::new_from_rng_128(&mut perm_rng);
    let mut ch = Chl::new(perm);
    for &f in public_bind {
        ch.observe(f);
    }
    ch
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// PROVE.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ⭐⭐⭐ PROVE a batch of AIRs with POST-COMMIT LogUp buses.
///
/// `tables` are the constraint tables as LAID (power-of-two heights); `make_constraint(i, gamma)` builds table `i`'s
/// γ-batched gate (wrapped here in [`BlindedRows`]); `buses` name, per bus, which columns of which tables send and receive
/// and with what multiplicity.
///
/// Returns the carrier bytes, or `None` on any shape, multiplicity, arity or `α`-collision refusal, or when the OS cannot
/// supply blinding randomness (fail-closed: a carrier that looks blinded but is not leaks exactly as an unblinded one).
/// Verify with [`verify_postcommit_bus_bytes`].
#[must_use]
pub fn prove_postcommit_bus_bytes<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    prove_inner(tables, make_constraint, buses, public_bind, Hooks::default())
}

/// The lie a test adversary tells about one round-1 table's zerocheck (constructed by test builds only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Forge {
    /// The opened row at `r` is SOLVED so the gate holds there; it is absorbed as the verifier absorbs a claim and never
    /// recorded on the commitment. The next-row values are the committed table's own.
    Row,
    /// The opened row is the commitment's own; ONE next-row value the gate reads is SOLVED so the gate holds.
    Next,
}

/// The refutation lanes' hooks. Only test builds set them; the public entry passes none.
#[derive(Default)]
struct Hooks<'a> {
    /// Rewrite the bus tables after they are built and before they are committed, knowing each bus's `(α, β)`.
    tamper: Option<&'a dyn Fn(&mut Vec<Vec<Vec<Fa4>>>, &[(Ea4, Fa4)])>,
    /// A round-1 table whose zerocheck the liar forges.
    forge: Option<(usize, Forge)>,
    /// Derive the `Free` sides' counts from THESE tables instead of the committed ones.
    count_from: Option<&'a [Vec<Vec<Fa4>>]>,
}

/// ⛔ TEST-ONLY ADVERSARY (A-F55's question for the CPU leg, A-F57's measurement): the honest prover in its exact transcript
/// order — both rounds committed, the buses honest, every next-row value the commitment's own and bound — except that
/// round-1 table `forge_table`'s zerocheck rounds are all ZERO and its opened row is SOLVED to satisfy its gate at the
/// rounds' point ([`Forge::Row`]). The door's whole claims replay accepts it; the opening of the commitment refuses it.
#[cfg(test)]
pub(crate) fn forge_postcommit_opened_for_tests<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    forge_table: usize,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    prove_inner(tables, make_constraint, buses, public_bind, Hooks { forge: Some((forge_table, Forge::Row)), ..Hooks::default() })
}

/// The forged zerocheck of [`Forge`]: zero rounds absorbed exactly as `verify_air_zerocheck_over` absorbs them, then the
/// committed table's own row and next-row values at the rounds' point `r`, one of them moved until the gate holds there.
/// A `Row` lie is absorbed as the verifier's `add_claim_at` absorbs it and never recorded on the commitment; a `Next` lie
/// rides the honest row (recorded) and is bound by the honest shift bind that follows.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn forged_zerocheck_for_tests<C: AirConstraint>(
    cst: &C,
    cols: &[Vec<Fa4>],
    nv: usize,
    w: usize,
    what: Forge,
    t: usize,
    prover: &mut LightCommitProver,
    ch: &mut Chl,
) -> Option<AirZerocheckProof> {
    let per = cst.degree(nv) + 2;
    let (mut round_evals, mut r) = (Vec::with_capacity(nv), Vec::with_capacity(nv));
    for _ in 0..nv {
        let h = vec![Ea4::ZERO; per];
        for e in &h {
            for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
                ch.observe(b);
            }
        }
        r.push(ch.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    let eq = crate::air_zerocheck::eq_z_hypercube(&r);
    let size = 1usize << nv;
    let mle = |c: &[Fa4], shift: usize| (0..size).fold(Ea4::ZERO, |a, i| a + eq[i] * Ea4::from(c[(i + shift) % size]));
    let row: Vec<Ea4> = cols.iter().map(|c| mle(c, 0)).collect();
    let next: Vec<Ea4> = cols.iter().map(|c| mle(c, 1)).collect();
    match what {
        Forge::Row => {
            let (mut opened, _) = crate::air_zerocheck::solve_one_coordinate_for_tests(cst, &row, &next, &r, false, &[])?;
            if opened == row {
                // a gate that holds at the committed row anyway: the liar still sends a row that is not the commitment's
                opened[0] += Ea4::ONE;
                opened = crate::air_zerocheck::solve_one_coordinate_for_tests(cst, &opened, &next, &r, false, &[])?.0;
                if opened == row {
                    return None;
                }
            }
            ch.observe_algebra_slice(&opened);
            Some(AirZerocheckProof { round_evals, opened, r, shifted_opened: next })
        }
        Forge::Next => {
            let set = shifted_set(cst, w);
            let all: Vec<usize> = (0..w).collect();
            let opened = prover.eval_at(t, &all, &Point::new(r.clone()), ch);
            let (_, lie) = crate::air_zerocheck::solve_one_coordinate_for_tests(cst, &opened, &next, &r, true, &set)?;
            if lie == next {
                return None;
            }
            Some(AirZerocheckProof { round_evals, opened, r, shifted_opened: lie })
        }
    }
}

/// ⭐ THE REFUTATION LANE. A prover that builds an HONEST bus table can never exercise the `r*` tie — the openings agree
/// by construction and the check passes for a verifier that does not look. `tamper` lets a pin rewrite the bus tables
/// AFTER they are built and BEFORE they are committed, knowing the challenges, which is exactly what a forger does.
#[cfg(test)]
fn prove_with_side_tamper<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    tamper: &dyn Fn(&mut Vec<Vec<Vec<Fa4>>>, &[(Ea4, Fa4)]),
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    prove_inner(tables, make_constraint, buses, public_bind, Hooks { tamper: Some(tamper), ..Hooks::default() })
}

/// The one prover body.
fn prove_inner<C, Mk>(
    tables: Vec<Vec<Vec<Fa4>>>,
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    hooks: Hooks<'_>,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    if tables.is_empty() || tables.len() > BUS_MAX_TABLES {
        return None;
    }
    let mut laid1 = Vec::with_capacity(tables.len());
    for cols in &tables {
        laid1.push(shape_of(cols)?);
    }
    if !spec_admissible(buses, &laid1) {
        return None;
    }
    let plan = BusPlan::of(buses, &laid1)?;
    // ⛔ FAIL-CLOSED ON ENTROPY (committed_air's rule): the blinding rows are the OS's or there is no proof.
    let mut rng = SmallRng::try_from_rng(&mut rand::rngs::SysRng::default()).ok()?;
    let mut ch = challenger(public_bind);
    // Phase profile: `MONEROUSD_BUS_PROFILE=1` prints where a prove's wall-clock goes. Nothing the proof depends on.
    let prof = std::env::var_os("MONEROUSD_BUS_PROFILE").is_some();
    let t0 = std::time::Instant::now();

    // ── ROUND 1: the counts appended (defect 4: committed BEFORE α), every table blinded, committed. ─────────────────
    let mut appends: Vec<(usize, Vec<Fa4>)> = Vec::new();
    {
        let counted: &[Vec<Vec<Fa4>>] = hooks.count_from.unwrap_or(tables.as_slice());
        for spec in buses {
            // H6: every side's multiplicities come from the round-1 tables, never from the caller.
            let mults = derive_side_multiplicities(spec, counted)?;
            for (k, side) in spec.sides.iter().enumerate() {
                if side.mult == BusMult::Free {
                    appends.push((side.table, mults.get(k)?.clone()));
                }
            }
        }
    }
    let mut src = tables;
    for (t, col) in appends {
        src.get_mut(t)?.push(col);
    }
    for (t, &(_, w)) in plan.committed1.iter().enumerate() {
        if src[t].len() != w {
            return None; // the appended columns sit exactly where the plan names them
        }
    }
    let blinded1: Vec<Vec<Vec<Fa4>>> = src.into_iter().map(|t| crate::committed_air::blind_cols(t, &mut rng)).collect();
    let mut prover1 = LightCommitProver::commit(blinded1.clone(), &mut ch)?;
    let t_r1 = t0.elapsed();

    // ── α and β, with the round-1 commitment already observed (DB-159). ─────────────────────────────────────────────
    let mut bus_ab: Vec<(Ea4, Fa4)> = Vec::with_capacity(buses.len());
    for _ in buses {
        let alpha: Ea4 = ch.sample_algebra_element();
        let beta = draw_bus_fold_challenge(&mut ch);
        bus_ab.push((alpha, beta));
    }

    // ── ROUND 2: one bus table per bus, which could not exist before α; blinded rows inside; committed. ─────────────
    let mut tables2: Vec<Vec<Vec<Fa4>>> = Vec::with_capacity(buses.len());
    for (b, spec) in buses.iter().enumerate() {
        tables2.push(bus_table(&blinded1, spec, &plan.mult_cols[b], &plan.layouts[b], bus_ab[b].0, bus_ab[b].1, &mut rng)?);
    }
    if let Some(t) = hooks.tamper {
        t(&mut tables2, &bus_ab);
    }
    for (t, &(nv, w)) in tables2.iter().zip(&plan.committed2) {
        if t.len() != w || t.iter().any(|c| c.len() != 1usize << nv) {
            return None;
        }
    }
    let mut prover2 = LightCommitProver::commit(tables2.clone(), &mut ch)?;
    let t_r2 = t0.elapsed();

    // ── r*: drawn after BOTH commitments, so neither side can be crafted to agree only there. ───────────────────────
    let star = plan.committed1.iter().chain(plan.committed2.iter()).map(|s| s.0).max()?;
    let r_star: Vec<Ea4> = (0..star).map(|_| ch.sample_algebra_element()).collect();
    let mut bus_proofs: Vec<BusProof> = Vec::with_capacity(buses.len());
    for (b, spec) in buses.iter().enumerate() {
        let lay = &plan.layouts[b];
        let p_bus = r_star[star - (lay.nvars + 1)..].to_vec();
        let mut ties = Vec::with_capacity(spec.sides.len());
        for (k, side) in spec.sides.iter().enumerate() {
            let (src_cols, bus_cols) = tie_cols(side, plan.mult_cols[b][k], &lay.sides[k]);
            let (p_src, _) = project(&p_bus, lay.sides[k].src_nvars);
            let src = prover1.eval_at(side.table, &src_cols, &Point::new(p_src), &mut ch);
            let bus = prover2.eval_at(b, &bus_cols, &Point::new(p_bus.clone()), &mut ch);
            ties.push(TieProof { src, bus });
        }
        bus_proofs.push(BusProof { alpha: bus_ab[b].0, beta: bus_ab[b].1, ties });
    }
    let t_tie = t0.elapsed();

    // ── γ, then every table's zerocheck: its row claimed on its commitment, its next-row values bound. ──────────────
    let gamma: Ea4 = ch.sample_algebra_element();
    let mut zcs1 = Vec::with_capacity(plan.committed1.len());
    let mut binds1 = Vec::with_capacity(plan.committed1.len());
    for (i, &(nv, w)) in plan.committed1.iter().enumerate() {
        let cst = BlindedRows { inner: make_constraint(i, gamma), appended: plan.appended[i].clone() };
        let set = shifted_set(&cst, w);
        let z: Vec<Ea4> = (0..nv).map(|_| ch.sample_algebra_element()).collect();
        let forge = hooks.forge.filter(|&(t, _)| t == i).map(|(_, f)| f);
        let mut zc = match forge {
            None => {
                let zc = prove_air_zerocheck(&blinded1[i], &cst, &z, &mut ch);
                let all: Vec<usize> = (0..w).collect();
                let _ = prover1.eval_at(i, &all, &Point::new(zc.r.clone()), &mut ch);
                zc
            }
            Some(what) => {
                #[cfg(test)]
                {
                    forged_zerocheck_for_tests(&cst, &blinded1[i], nv, w, what, i, &mut prover1, &mut ch)?
                }
                #[cfg(not(test))]
                {
                    let _ = what;
                    return None; // the forge hook exists only for the test adversary
                }
            }
        };
        compact_shifted(&mut zc, &set);
        absorb_shifted_openings(&mut ch, &zc.shifted_opened);
        binds1.push(if set.is_empty() {
            None
        } else {
            Some(prove_shift_bind(&blinded1[i], &set, &zc.r, i, &mut prover1, &mut ch))
        });
        zcs1.push(zc);
    }
    let mut zcs2 = Vec::with_capacity(plan.committed2.len());
    let mut binds2 = Vec::with_capacity(plan.committed2.len());
    for (b, &(nv, w)) in plan.committed2.iter().enumerate() {
        let cst = BlindedRows { inner: bus_run(&plan.layouts[b], bus_ab[b], gamma), appended: Vec::new() };
        let set = shifted_set(&cst, w);
        let z: Vec<Ea4> = (0..nv).map(|_| ch.sample_algebra_element()).collect();
        let mut zc = prove_air_zerocheck(&tables2[b], &cst, &z, &mut ch);
        let all: Vec<usize> = (0..w).collect();
        let _ = prover2.eval_at(b, &all, &Point::new(zc.r.clone()), &mut ch);
        compact_shifted(&mut zc, &set);
        absorb_shifted_openings(&mut ch, &zc.shifted_opened);
        binds2.push(if set.is_empty() {
            None
        } else {
            Some(prove_shift_bind(&tables2[b], &set, &zc.r, b, &mut prover2, &mut ch))
        });
        zcs2.push(zc);
    }
    let t_zc = t0.elapsed();

    // ── Two WHIR openings, one per commitment, in this order. ───────────────────────────────────────────────────────
    let light1 = prover1.finish(&mut ch);
    let light2 = prover2.finish(&mut ch);
    if prof {
        let ms = |d: std::time::Duration| d.as_millis();
        let t_all = t0.elapsed();
        eprintln!(
            "[bus-profile] round1 committed {:?} bus tables {:?} | round1 commit {} ms | bus tables commit {} ms | ties {} ms | zerochecks + shift binds {} ms | openings {} ms | total {} ms",
            plan.committed1,
            plan.committed2,
            ms(t_r1),
            ms(t_r2 - t_r1),
            ms(t_tie - t_r2),
            ms(t_zc - t_tie),
            ms(t_all - t_zc),
            ms(t_all)
        );
    }
    let round1 = RoundBundle { shapes: laid1, zcs: zcs1, binds: binds1, light: light1 };
    let round2 = RoundBundle { shapes: plan.laid2.clone(), zcs: zcs2, binds: binds2, light: light2 };
    postcard::to_allocvec(&PostCommitBusBundle { round1, round2, buses: bus_proofs }).ok()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// VERIFY.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ⛔ TEST-ONLY: the `(round 1, round 2)` LAID table shapes a post-commit bus carrier DECLARES — the pre-DB-213b input to
/// its verify. For tests whose subject is not the shape; no shipped binary carries it.
#[cfg(test)]
#[must_use]
pub(crate) fn declared_postcommit_shapes_for_tests(bytes: &[u8]) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    postcard::from_bytes::<PostCommitBusBundle>(bytes)
        .map(|b| (b.round1.shapes.clone(), b.round2.shapes.clone()))
        .unwrap_or_default()
}

/// ⭐⭐⭐ VERIFY a post-commit-bus carrier. Replays the prover's transcript in EXACT order: the statement's shapes, both
/// commitments observed before the challenges that depend on them, `α`/`β` re-derived and bound, every tie, every
/// zerocheck (the bus tables' running-sum laws are the bus verdict), every shift bind — then the two WHIR openings, which
/// discharge every claim against the commitments. Fail-closed on any mismatch; never panics on a hostile carrier.
///
/// `buses` is the PUBLIC spec both sides know — the verifier takes each side's source table and key columns from it,
/// never from the carrier, so a prover cannot re-point a side at a different column. `expected_round1` /
/// `expected_round2` are the LAID shapes the statement fixes (DB-213b): round 2's are [`bus_table_shapes`] of round 1's.
pub fn verify_postcommit_bus_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    expected_round1: &[(usize, usize)],
    expected_round2: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    let Ok(bundle) = postcard::from_bytes::<PostCommitBusBundle>(bytes) else { return false };
    match replay_through_claims(&bundle, make_constraint, buses, public_bind, expected_round1, expected_round2) {
        Some((v1, v2, mut ch)) => v1.finish(&mut ch) && v2.finish(&mut ch),
        None => false,
    }
}

/// ⛔ TEST-ONLY: does the verifier's replay accept every CLAIM of this carrier — everything [`verify_postcommit_bus_bytes`]
/// checks short of the two openings? The calibration that makes a refusal attributable to the commitment.
#[cfg(test)]
pub(crate) fn claims_replay_accepts_for_tests<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    expected_round1: &[(usize, usize)],
    expected_round2: &[(usize, usize)],
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    let Ok(bundle) = postcard::from_bytes::<PostCommitBusBundle>(bytes) else { return false };
    replay_through_claims(&bundle, make_constraint, buses, public_bind, expected_round1, expected_round2).is_some()
}

/// One table's zerocheck replayed: the lengths against the committed width and the public next-row set (before anything
/// is sized by them), the zerocheck over that set, the row claimed at `r`, the next-row values absorbed and bound.
#[allow(clippy::too_many_arguments)]
fn replay_table<C: AirConstraint>(
    cst: &C,
    nv: usize,
    w: usize,
    zc: &AirZerocheckProof,
    bind: Option<&ShiftBindProof>,
    t: usize,
    v: &mut LightCommitVerifier<'_>,
    ch: &mut Chl,
) -> bool {
    let set = shifted_set(cst, w);
    if zc.opened.len() != w || zc.r.len() != nv || zc.shifted_opened.len() != set.len() || bind.is_some() == set.is_empty() {
        return false;
    }
    let z: Vec<Ea4> = (0..nv).map(|_| ch.sample_algebra_element()).collect();
    if !verify_air_zerocheck_over(zc, cst, &z, ch, &set) {
        return false;
    }
    let all: Vec<usize> = (0..w).collect();
    v.add_claim_at(t, &all, &zc.opened, &Point::new(zc.r.clone()), ch);
    absorb_shifted_openings(ch, &zc.shifted_opened);
    match bind {
        Some(sb) => verify_shift_bind(sb, &zc.r, &zc.shifted_opened, &set, t, v, ch),
        None => true,
    }
}

/// The verifier's replay THROUGH EVERY CLAIM, in the prover's exact order. Returns both rounds' claim registries and the
/// transcript as they stand before the two openings, or `None` on any mismatch. ONE definition, read by
/// [`verify_postcommit_bus_bytes`] and by the tests' calibration, so the two can never replay different statements.
#[allow(clippy::type_complexity)]
fn replay_through_claims<'b, C, Mk>(
    bundle: &'b PostCommitBusBundle,
    make_constraint: Mk,
    buses: &[BusSpec],
    public_bind: &[Fa4],
    expected_round1: &[(usize, usize)],
    expected_round2: &[(usize, usize)],
) -> Option<(LightCommitVerifier<'b>, LightCommitVerifier<'b>, Chl)>
where
    C: AirConstraint + Sync,
    Mk: Fn(usize, Ea4) -> C,
{
    let (b1, b2) = (&bundle.round1, &bundle.round2);
    if b1.shapes != expected_round1 || b2.shapes != expected_round2 {
        return None; // ⛔ DB-213b — not the statement's shapes
    }
    if b1.shapes.is_empty() || b1.shapes.len() > BUS_MAX_TABLES || bundle.buses.len() != buses.len() {
        return None;
    }
    if b1.shapes.iter().any(|&(nv, w)| nv > BUS_MAX_NVARS || w == 0 || w > BUS_MAX_TABLE_WIDTH) {
        return None;
    }
    if !spec_admissible(buses, &b1.shapes) {
        return None;
    }
    let plan = BusPlan::of(buses, &b1.shapes)?;
    if plan.laid2 != b2.shapes
        || b1.zcs.len() != b1.shapes.len()
        || b1.binds.len() != b1.shapes.len()
        || b2.zcs.len() != b2.shapes.len()
        || b2.binds.len() != b2.shapes.len()
    {
        return None;
    }
    let mut ch = challenger(public_bind);

    // Mirror ROUND 1's commitment, then the α/β draw.
    let mut v1 = LightCommitVerifier::begin(&plan.committed1, &b1.light, &mut ch)?;
    let mut bus_ab: Vec<(Ea4, Fa4)> = Vec::with_capacity(buses.len());
    for bp in &bundle.buses {
        let alpha: Ea4 = ch.sample_algebra_element();
        let beta = draw_bus_fold_challenge(&mut ch);
        // ⛔ BIND them: a carrier naming its own α would be a carrier choosing its own challenge.
        if alpha != bp.alpha || beta != bp.beta {
            return None;
        }
        bus_ab.push((alpha, beta));
    }

    // Mirror ROUND 2's commitment, then r* and every tie.
    let mut v2 = LightCommitVerifier::begin(&plan.committed2, &b2.light, &mut ch)?;
    let star = plan.committed1.iter().chain(plan.committed2.iter()).map(|s| s.0).max()?;
    let r_star: Vec<Ea4> = (0..star).map(|_| ch.sample_algebra_element()).collect();
    for (b, spec) in buses.iter().enumerate() {
        let bp = &bundle.buses[b];
        if bp.ties.len() != spec.sides.len() {
            return None;
        }
        let lay = &plan.layouts[b];
        let p_bus = r_star[star - (lay.nvars + 1)..].to_vec();
        for (k, side) in spec.sides.iter().enumerate() {
            // The side's TABLE, SOURCE and tied column set are dictated by the public spec, not by the carrier.
            let (src_cols, bus_cols) = tie_cols(side, plan.mult_cols[b][k], &lay.sides[k]);
            let tie = &bp.ties[k];
            if tie.src.len() != src_cols.len() || tie.bus.len() != bus_cols.len() {
                return None;
            }
            let (p_src, scale) = project(&p_bus, lay.sides[k].src_nvars);
            v1.add_claim_at(side.table, &src_cols, &tie.src, &Point::new(p_src), &mut ch);
            v2.add_claim_at(b, &bus_cols, &tie.bus, &Point::new(p_bus.clone()), &mut ch);
            // THE TIE: the bus table's copy is the source's column, at its height, at r*
            if tie.bus.iter().zip(&tie.src).any(|(&s, &c)| s != scale * c) {
                return None;
            }
        }
    }

    // Mirror γ and every zerocheck.
    let gamma: Ea4 = ch.sample_algebra_element();
    for (i, &(nv, w)) in plan.committed1.iter().enumerate() {
        let cst = BlindedRows { inner: make_constraint(i, gamma), appended: plan.appended[i].clone() };
        if !replay_table(&cst, nv, w, &b1.zcs[i], b1.binds[i].as_ref(), i, &mut v1, &mut ch) {
            return None;
        }
    }
    for (b, &(nv, w)) in plan.committed2.iter().enumerate() {
        let cst = BlindedRows { inner: bus_run(&plan.layouts[b], bus_ab[b], gamma), appended: Vec::new() };
        if !replay_table(&cst, nv, w, &b2.zcs[b], b2.binds[b].as_ref(), b, &mut v2, &mut ch) {
            return None;
        }
    }
    Some((v1, v2, ch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_zerocheck::Row;

    /// The WHIR `nvars >= 5` floor this crate already pins the same way.
    const ROWS: usize = 32;
    /// The statement. It is the SAME for every trace in these pins, which is the whole point: if `α`
    /// moved with the statement alone, DB-159 would still be open.
    const BIND: [Fa4; 1] = [Fa4::new(0x5043_4200)]; // "PCB\0"

    /// A gate that constrains nothing. These pins measure the BUS, and a constraint that could fail would
    /// make a refusal ambiguous — the question here is only ever "did the bus balance".
    struct NullGate;
    impl AirConstraint for NullGate {
        fn degree(&self, _nvars: usize) -> usize {
            8
        }
        fn eval(&self, _l: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            Ea4::ZERO
        }
        /// A gate with no laws leaves every one of its columns to the BUS this test exercises (the bus table's laws tie each
        /// key column to its source). MEASURED 2026-11-16 (lane af58, F6 door-value G8 on the debug test binary): undeclared,
        /// `BlindedRows<NullGate>` turned the free-witness census into a refusal of columns 0..2 and all seven bus pins
        /// panicked before reaching their assertion. Test fixture only; every production gate declares its own.
        fn free_columns(&self) -> Option<Vec<usize>> {
            Some((0..256).collect())
        }
    }
    fn gates(_i: usize, _g: Ea4) -> NullGate {
        NullGate
    }

    fn fe(v: u64) -> Fa4 {
        Fa4::from_u64(v)
    }

    /// A tiny fetch bus, in the shape the DSOL zkVM needs it: a CPU table whose rows each FETCH one
    /// instruction, and a ROM table holding the program. The bus balances iff every fetch names a row the
    /// program actually contains.
    ///
    /// `bad_op` rewrites one CPU row's opcode to something the ROM does not hold — the forgery the whole
    /// mechanism exists to refuse.
    fn fetch_tables(bad_op: Option<u64>) -> (Vec<Vec<Vec<Fa4>>>, Vec<BusSpec>) {
        // ROM: four instructions at pc 0..3, then padding. Its multiplicities are the prover's to derive
        // (`BusMult::Free`): each instruction is fetched ROWS/4 times by the walk below.
        let prog: [(u64, u64, u64); 4] = [(0, 0x01, 7), (1, 0x10, 0), (2, 0x31, 9), (3, 0x32, 0)];
        let mut rom = vec![vec![Fa4::ZERO; ROWS]; 3];
        for (j, &(pc, op, imm)) in prog.iter().enumerate() {
            rom[0][j] = fe(pc);
            rom[1][j] = fe(op);
            rom[2][j] = fe(imm);
        }
        // CPU: a walk that fetches each instruction the same number of times. Column 3 is its `real`
        // flag — the multiplicity the bus reads (`BusMult::Column(3)`); every row of this walk is real.
        let mut cpu = vec![vec![Fa4::ZERO; ROWS]; 4];
        for r in 0..ROWS {
            let (pc, op, imm) = prog[r % prog.len()];
            cpu[0][r] = fe(pc);
            cpu[1][r] = fe(op);
            cpu[2][r] = fe(imm);
            cpu[CPU_REAL][r] = Fa4::ONE;
        }
        if let Some(o) = bad_op {
            // ⛔ THE ATTACK: one row executes an opcode this program does not contain.
            cpu[1][0] = fe(o);
        }
        let spec = BusSpec {
            sides: vec![
                BusSide { table: 0, cols: vec![0, 1, 2], mult: BusMult::Column(CPU_REAL) },
                BusSide { table: 1, cols: vec![0, 1, 2], mult: BusMult::Free },
            ],
        };
        (vec![cpu, rom], vec![spec])
    }
    /// The fixture CPU's `real` column.
    const CPU_REAL: usize = 3;

    fn verify(proof: &[u8], buses: &[BusSpec]) -> bool {
        let (s1, s2) = declared_postcommit_shapes_for_tests(proof);
        verify_postcommit_bus_bytes(proof, gates, buses, &BIND, &s1, &s2)
    }

    /// The fixture's bus table layout, as the engine lays it.
    fn layout_of(tables: &[Vec<Vec<Fa4>>], buses: &[BusSpec]) -> BusLayout {
        let laid: Vec<(usize, usize)> = tables.iter().map(|t| shape_of(t).expect("a fixture shape")).collect();
        bus_layout(&buses[0], &laid).expect("the fixture's bus lays out")
    }

    fn ext_at(t: &[Vec<Fa4>], base: usize, row: usize) -> Ea4 {
        (0..EXT_D).fold(Ea4::ZERO, |a, l| a + Ea4::from(t[base + l][row]) * basis(l))
    }

    /// Re-run a bus table's running sum over its data half from its `h` columns (a tamper that moves an `h` keeps the
    /// running-sum law), and say whether the bus balances (it ends at zero).
    fn rerun_acc(t: &mut [Vec<Fa4>], lay: &BusLayout) -> bool {
        let half = t[0].len() / 2;
        let mut acc = Ea4::ZERO;
        for i in 0..half {
            for (l, v) in limbs(acc).into_iter().enumerate() {
                t[lay.acc_base + l][i] = v;
            }
            for s in &lay.sides {
                acc += ext_at(t, s.h_base, i);
            }
        }
        acc == Ea4::ZERO
    }

    /// ⭐⭐⭐ THE HONEST CARRIER PROVES, AND AN INDEPENDENT VERIFIER ACCEPTS IT. Calibration first: without
    /// this, every refusal below would be consistent with a mechanism that refuses everything.
    #[test]
    fn an_honest_fetch_bus_proves_and_an_independent_verifier_accepts_it() {
        let (tables, buses) = fetch_tables(None);
        let proof = prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).expect("an honest fetch bus proves");
        assert!(verify(&proof, &buses), "an independently-derived verifier must accept an honest post-commit bus");
        eprintln!("[postcommit-bus] honest two-round carrier = {} byte(s)", proof.len());
    }

    /// ⭐⭐⭐ THE MEASUREMENT THAT CLOSES DB-159 — `α` MOVES WITH THE TRACE, NOT WITH THE STATEMENT.
    ///
    /// Under the old ordering `α` was drawn from a transcript holding only `public_bind`, so two different
    /// traces under one statement got the SAME challenge and a prover could compute it before choosing
    /// what to commit. This drives exactly that: one statement, two traces that differ in a single cell,
    /// and the challenge must differ. If these two `α`s were equal, the fix would be decoration.
    #[test]
    fn the_bus_challenge_moves_when_the_trace_moves_under_one_unchanged_statement() {
        let decode = |bytes: &[u8]| -> (Ea4, Fa4) {
            let b: PostCommitBusBundle = postcard::from_bytes(bytes).expect("the carrier decodes");
            (b.buses[0].alpha, b.buses[0].beta)
        };
        let (t1, buses) = fetch_tables(None);
        let p1 = prove_postcommit_bus_bytes(t1, gates, &buses, &BIND).expect("trace one proves");

        // A SECOND trace under the SAME statement: the same fetch multiset (so the bus still balances),
        // but one instruction's immediate differs, so the committed columns differ.
        let (mut t2, buses2) = fetch_tables(None);
        // Instruction 0's immediate changes. The walk fetches it on every 4th row, so EVERY one of those
        // rows moves with it — otherwise the multiset stops agreeing and this pin would be measuring an
        // unbalanced bus instead of a moving challenge.
        t2[1][2][0] = fe(1_234);
        for r in (0..ROWS).step_by(4) {
            t2[0][2][r] = fe(1_234);
        }
        let p2 = prove_postcommit_bus_bytes(t2, gates, &buses2, &BIND).expect("trace two proves");
        assert!(verify(&p2, &buses2), "PRECONDITION: the second trace is honest too, or the comparison below is meaningless");

        let (a1, b1) = decode(&p1);
        let (a2, b2) = decode(&p2);
        assert_ne!(
            a1, a2,
            "⛔ DB-159 IS STILL OPEN. One statement, two different committed traces, and the bus \
             challenge did not move — so a prover can still compute α before it chooses what to commit, \
             which is the whole defect this module was written to close."
        );
        assert_ne!(b1, b2, "and the key-fold challenge moves with it, for the same reason");
        eprintln!("[postcommit-bus] one statement, two traces ⇒ two challenges (DB-159 closed)");
    }

    /// ⛔⛔⛔ A FETCH THE PROGRAM DOES NOT CONTAIN IS REFUSED. This is the law the DSOL zkVM's L2 rests
    /// on: without it a proof says a computation happened, not that THIS CONTRACT ran.
    #[test]
    fn a_fetch_of_an_instruction_the_program_does_not_contain_is_refused() {
        let (tables, buses) = fetch_tables(Some(0xEE));
        match prove_postcommit_bus_bytes(tables, gates, &buses, &BIND) {
            // The prover may still emit a carrier — an unbalanced bus is a real set of columns. The
            // VERDICT is the verifier's, and it must be a refusal.
            Some(proof) => assert!(
                !verify(&proof, &buses),
                "⛔ AN UNBALANCED FETCH BUS VERIFIED — a row executed opcode 0xEE, which this program \
                 does not contain, and the carrier was accepted anyway"
            ),
            None => {} // refused at build time is also a refusal
        }
    }

    /// ⛔⛔⛔ A BUS TABLE THAT DOES NOT HOLD ITS SOURCE'S COLUMNS IS REFUSED — the `r*` tie, measured.
    ///
    /// A forger's move is not to unbalance the bus; it is to commit a bus table whose keys are whatever
    /// makes the sum cancel, divorced from the trace the constraints actually ran over. Copies bind
    /// nothing on their own, so this rewrites one committed bus cell and the tie must catch it.
    #[test]
    fn a_side_table_whose_key_columns_are_not_the_sources_is_refused() {
        let (tables, buses) = fetch_tables(None);
        let proof = prove_with_side_tamper(tables, gates, &buses, &BIND, &|t2: &mut Vec<Vec<Vec<Fa4>>>, _ab: &[(Ea4, Fa4)]| {
            // The bus table's CPU side is `[pc | op | imm | mult | h0..h3]` from column 0. Move the opcode
            // column's first cell — the key the bus folds — away from what the source holds.
            t2[0][1][0] = fe(0x99);
        })
        .expect("a tampered carrier still serializes — the verdict is the verifier's");
        assert!(
            !verify(&proof, &buses),
            "⛔ A BUS TABLE DIVORCED FROM ITS SOURCE VERIFIED. The r* tie is the only thing making a \
             bus key a value the trace actually holds; without it the whole bus is a free-floating sum."
        );
    }

    /// ⛔ A CARRIER THAT NAMES ITS OWN CHALLENGE IS REFUSED. `α` rides the carrier so a reader can see it;
    /// it must still be the one the transcript produces, or the carrier chooses its own randomness.
    #[test]
    fn a_carrier_that_names_a_different_challenge_is_refused() {
        let (tables, buses) = fetch_tables(None);
        let proof = prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).expect("honest");
        let mut b: PostCommitBusBundle = postcard::from_bytes(&proof).expect("decodes");
        b.buses[0].alpha += Ea4::ONE;
        let forged = postcard::to_allocvec(&b).expect("re-encodes");
        assert!(!verify(&forged, &buses), "a carrier-chosen α must be refused");
    }

    /// ⛔⛔⛔ H6, THE TIE ON THE MULTIPLICITY COLUMN, MEASURED IN ISOLATION. A forger who cannot balance the bus
    /// against a forged row has one move left: commit a bus table whose multiplicity for that row is ZERO, so
    /// the bus never asks about it. Here the bus table is kept INTERNALLY consistent (`h · (α − key) = mult`
    /// holds on every row, the running sum is re-run) and BALANCED (the ROM side's copy for that instruction is
    /// lowered by one and its `h` rescaled to match), so the only thing left to refuse is the tie between the
    /// bus table's multiplicity copies and the source columns — and it must.
    #[test]
    fn a_side_table_whose_multiplicity_copy_is_not_the_sources_is_refused() {
        let (tables, buses) = fetch_tables(None);
        let lay = layout_of(&tables, &buses);
        let balanced = std::cell::Cell::new(false);
        let tamper = |t2: &mut Vec<Vec<Vec<Fa4>>>, _ab: &[(Ea4, Fa4)]| {
            let t = &mut t2[0];
            let (cpu, rom) = (&lay.sides[0], &lay.sides[1]);
            // CPU side, row 0: multiplicity copy → 0, its h → 0 (0 / (α − key) = 0: the keyfold law holds).
            t[cpu.mult_col][0] = Fa4::ZERO;
            for k in 0..EXT_D {
                t[cpu.h_base + k][0] = Fa4::ZERO;
            }
            // ROM side, row 0 (the instruction CPU row 0 fetches): −8 receives → −7, h scaled by 7/8.
            let h_new = ext_at(t, rom.h_base, 0) * Ea4::from(fe(7)) * Ea4::from(fe(8)).inverse();
            t[rom.mult_col][0] = Fa4::ZERO - fe(7);
            for (k, v) in limbs(h_new).into_iter().enumerate() {
                t[rom.h_base + k][0] = v;
            }
            balanced.set(rerun_acc(t, &lay));
        };
        let proof = prove_with_side_tamper(tables, gates, &buses, &BIND, &tamper)
            .expect("a tampered carrier still serializes — the verdict is the verifier's");
        assert!(balanced.get(), "CALIBRATION: the tamper keeps the bus balanced, so only the tie can refuse it");
        assert!(
            !verify(&proof, &buses),
            "⛔ H6 IS OPEN AGAIN: a bus table whose multiplicity copy differs from the source's constrained column \
             verified — a forger zeroes a forged row's multiplicity and the bus never asks the table about it."
        );
    }

    /// ⭐ THE CONTRACT A `BusMult::Column` SIDE RESTS ON, shown rather than asserted: the bus ties the multiplicity
    /// to the SOURCE column, and the source table's AIR is what gives that column its meaning. Under a gate that
    /// constrains nothing, a CPU whose row 0 fetches an opcode the program lacks AND carries `real = 0` on that row
    /// balances — the bus is doing its job (it counts what the column says is real). The refusal belongs to the
    /// source AIR's law on that column (the DSOL CPU's `real` laws, pinned in `dsol_cpu_air::fetch_tests`), and
    /// this calibration is what makes that pin's refusal attributable.
    #[test]
    fn a_zeroed_multiplicity_hides_a_forged_row_from_the_bus_so_the_source_air_must_constrain_it() {
        let (mut tables, buses) = fetch_tables(Some(0xEE));
        tables[0][CPU_REAL][0] = Fa4::ZERO; // "row 0 is padding", says the prover; nothing here disagrees
        let proof = prove_postcommit_bus_bytes(tables, gates, &buses, &BIND)
            .expect("CALIBRATION: with row 0 unreal the remaining fetches balance and the bus proves");
        assert!(verify(&proof, &buses), "CALIBRATION: under a constraint-free gate the bus accepts what the (unconstrained) real column says");
        eprintln!("[postcommit-bus] a Column side is only as sound as the AIR law on its column — calibrated");
    }

    /// ⛔ A BUS WHOSE EVERY SIDE IS THE PROVER'S TO DERIVE, OR WITH TWO SUCH SIDES, IS REFUSED BEFORE ANYTHING IS
    /// COMMITTED — all-zero balances the first, and the second lets the prover pick where a count lands.
    #[test]
    fn a_bus_with_no_column_side_or_two_free_sides_is_refused_before_anything_is_committed() {
        let (tables, mut buses) = fetch_tables(None);
        buses[0].sides[0].mult = BusMult::Free;
        assert!(prove_postcommit_bus_bytes(tables.clone(), gates, &buses, &BIND).is_none(), "two free sides: refused");
        let (tables, mut buses) = fetch_tables(None);
        buses[0].sides.push(BusSide { table: 1, cols: vec![0, 1, 2], mult: BusMult::Free });
        assert!(prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).is_none(), "a second free side: refused");
        // and a Column side pointing past its table's width
        let (tables, mut buses) = fetch_tables(None);
        buses[0].sides[0].mult = BusMult::Column(99);
        assert!(prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).is_none(), "a mult column past the width: refused");
    }

    /// ⛔ A ONE-SIDED BUS IS NOT A BUS. It balances against itself and proves nothing, so it is refused
    /// before anything is committed rather than proved and believed.
    #[test]
    fn a_one_sided_bus_is_refused_before_anything_is_committed() {
        let (tables, mut buses) = fetch_tables(None);
        buses[0].sides.truncate(1);
        assert!(prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).is_none(), "a one-sided bus must be refused");
    }

    /// ⛔ A SPEC POINTING PAST ITS TABLE IS REFUSED — a remote sender's declared shape must never become
    /// an allocation or an out-of-range read.
    #[test]
    fn a_spec_that_points_past_its_table_is_refused() {
        let (tables, mut buses) = fetch_tables(None);
        buses[0].sides[0].cols = vec![0, 1, 99];
        assert!(prove_postcommit_bus_bytes(tables, gates, &buses, &BIND).is_none(), "a key column past the table's width must be refused");
    }

    /// ⛔⛔⛔ A-F57 (defect 1), AT THE ENGINE: A CARRIER WHOSE OPENED ROW IS NOT THE COMMITMENT'S IS REFUSED BY THE OPENING.
    /// The liar commits the honest tables and sends round-1 table 0's zerocheck as zero rounds with an opened row that is
    /// not the committed row at `r` (`Forge::Row`); everything else is honest. CALIBRATION: the verifier's whole claims
    /// replay accepts it — the shapes, α/β, every tie, every zerocheck, every shift bind — so the refusal is the WHIR
    /// opening's and nothing else's. On the old engine every claim verified as whatever it said (`verify_hvzk` dropped the
    /// target): the same lie at the DSOL door was MEASURED accepted (`dsol_cpu_air::fetch_tests::af55_…`, 2026-11-15).
    /// TWO-PARTY-REVIEWED: the parties are the lying prover and `verify_postcommit_bus_bytes`, which rebuilds every
    /// challenge and every shape from the statement.
    #[test]
    fn a_carrier_whose_opened_row_is_not_the_commitments_is_refused_by_the_opening() {
        let (tables, buses) = fetch_tables(None);
        let forged = prove_inner(tables, gates, &buses, &BIND, Hooks { forge: Some((0, Forge::Row)), ..Hooks::default() })
            .expect("the liar's carrier serializes");
        let (s1, s2) = declared_postcommit_shapes_for_tests(&forged);
        assert!(
            claims_replay_accepts_for_tests(&forged, gates, &buses, &BIND, &s1, &s2),
            "CALIBRATION: every claim-level check accepts the liar; only the opening can refuse it"
        );
        assert!(!verify(&forged, &buses), "⛔⛔⛔ A-F57: an opened row that is not the committed row VERIFIED");
    }

    /// A gate that reads the NEXT row: column `COUNTER` of table 0 counts up by one on every data row but the last.
    struct CounterGate {
        on: bool,
    }
    const COUNTER: usize = 4;
    impl AirConstraint for CounterGate {
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        fn shifted_cols(&self) -> Option<Vec<usize>> {
            Some(if self.on { vec![COUNTER] } else { Vec::new() })
        }
        /// Its one law reads the counter column; every other column is the bus's (NullGate's note: the census refused 0..2).
        fn free_columns(&self) -> Option<Vec<usize>> {
            Some((0..256).filter(|c| !(self.on && *c == COUNTER)).collect())
        }
        fn eval(&self, l: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
            if !self.on {
                return Ea4::ZERO;
            }
            let last = x.iter().fold(Ea4::ONE, |a, &v| a * v);
            (Ea4::ONE - last) * (at(COUNTER, &[]) - l[COUNTER] - Ea4::ONE)
        }
    }

    /// ⛔⛔⛔ A-F57 (defect 3): A CARRIER WHOSE NEXT-ROW VALUES ARE NOT THE COMMITMENT'S IS REFUSED. Table 0's gate reads the
    /// next row (a counter). The liar sends the committed row at `r` (recorded on the commitment) and ONE next-row value
    /// SOLVED so the gate holds there (`Forge::Next`); the shift bind that follows is the honest one. On the old engine
    /// next-row values were only absorbed, never bound (`absorb_shifted_openings` alone). CALIBRATION: the honest counter
    /// verifies, next-row values and all, so the refusal is the lie's.
    #[test]
    fn a_carrier_whose_next_row_values_are_not_the_commitments_is_refused() {
        let (mut t, buses) = fetch_tables(None);
        t[0].push((0..ROWS).map(|r| fe(r as u64)).collect());
        let g = |i: usize, _g: Ea4| CounterGate { on: i == 0 };
        let honest = prove_postcommit_bus_bytes(t.clone(), g, &buses, &BIND).expect("the honest counter proves");
        let (s1, s2) = declared_postcommit_shapes_for_tests(&honest);
        assert!(verify_postcommit_bus_bytes(&honest, g, &buses, &BIND, &s1, &s2), "CALIBRATION: the honest counter verifies");
        let forged = prove_inner(t, g, &buses, &BIND, Hooks { forge: Some((0, Forge::Next)), ..Hooks::default() })
            .expect("CALIBRATION: the liar solves a next-row value for the counter gate");
        assert!(
            !verify_postcommit_bus_bytes(&forged, g, &buses, &BIND, &s1, &s2),
            "⛔⛔⛔ A-F57: a next-row value that is not the committed rotation VERIFIED"
        );
    }

    /// Solve `Σ_j δ_j · c_j = rhs` for four BASE-field `δ_j` (four extension values `c_j`, one extension value `rhs`: four
    /// base-field equations in four unknowns, by Gaussian elimination).
    fn solve_base_4(c: &[Ea4], rhs: Ea4) -> Option<[Fa4; 4]> {
        let mut a: Vec<[Fa4; 5]> = (0..4)
            .map(|k| {
                let mut row = [Fa4::ZERO; 5];
                for j in 0..4 {
                    row[j] = limbs(c[j])[k];
                }
                row[4] = limbs(rhs)[k];
                row
            })
            .collect();
        for col in 0..4 {
            let p = (col..4).find(|&r| a[r][col] != Fa4::ZERO)?;
            a.swap(col, p);
            let inv = a[col][col].inverse();
            for x in a[col].iter_mut() {
                *x *= inv;
            }
            let pivot = a[col];
            for (r, row) in a.iter_mut().enumerate() {
                if r != col && row[col] != Fa4::ZERO {
                    let f = row[col];
                    for k in 0..5 {
                        row[k] -= f * pivot[k];
                    }
                }
            }
        }
        Some([a[0][4], a[1][4], a[2][4], a[3][4]])
    }

    /// ⛔⛔⛔ A-F57 (defect 4): A FREE SIDE'S COUNTS CHOSEN AFTER α CANNOT BALANCE A FETCH THE PROGRAM LACKS.
    /// The CPU commits a row fetching opcode 0xEE, which the ROM does not hold; the counts are derived as if it had
    /// fetched instruction 0. Knowing α and β, the liar moves four ROM rows' counts in the bus table by the base-field
    /// solution of `Σ_j δ_j/(α − t_j) = −(the imbalance)` — four equations, four unknowns — and re-runs the running sum.
    /// CALIBRATION: the bus then BALANCES. That is exactly what the old engine's untied `Free` side, laid after α, admitted
    /// (`tie_cols` left it out). Here the counts are a round-1 column, committed before α and tied at `r*`, so the tie
    /// refuses the moved counts.
    #[test]
    fn a_free_sides_counts_chosen_after_alpha_cannot_balance_a_fetch_the_program_lacks() {
        let (honest, buses) = fetch_tables(None);
        let (forged, _) = fetch_tables(Some(0xEE));
        let lay = layout_of(&forged, &buses);
        let balanced = std::cell::Cell::new(false);
        let tamper = |t2: &mut Vec<Vec<Vec<Fa4>>>, ab: &[(Ea4, Fa4)]| {
            let (alpha, beta) = ab[0];
            let t = &mut t2[0];
            let half = t[0].len() / 2;
            let rom = &lay.sides[1];
            let key = |t: &[Vec<Fa4>], row: usize| -> Ea4 {
                let mut k = Ea4::ZERO;
                let mut bp = Ea4::from(beta);
                for j in 0..rom.n_val {
                    k += bp * Ea4::from(t[rom.val_base + j][row]);
                    bp *= Ea4::from(beta);
                }
                k
            };
            let mut total = Ea4::ZERO;
            for i in 0..half {
                for s in &lay.sides {
                    total += ext_at(t, s.h_base, i);
                }
            }
            let c: Vec<Ea4> = (0..4).map(|j| (alpha - key(t, j)).inverse()).collect();
            let Some(delta) = solve_base_4(&c, Ea4::ZERO - total) else { return };
            for j in 0..4 {
                t[rom.mult_col][j] += delta[j];
                let h = Ea4::from(t[rom.mult_col][j]) * c[j];
                for (l, v) in limbs(h).into_iter().enumerate() {
                    t[rom.h_base + l][j] = v;
                }
            }
            balanced.set(rerun_acc(t, &lay));
        };
        let proof = prove_inner(forged, gates, &buses, &BIND, Hooks { tamper: Some(&tamper), count_from: Some(honest.as_slice()), ..Hooks::default() })
            .expect("the liar's carrier serializes");
        assert!(balanced.get(), "CALIBRATION: counts chosen after α balance a fetch the program does not contain");
        assert!(
            !verify(&proof, &buses),
            "⛔⛔⛔ A-F57 defect 4: counts chosen after α balanced a fetch of an opcode the program does not contain, and it VERIFIED"
        );
    }

    /// ⭐ §BE-1, MEASURED: A BLINDED CONSTANT COLUMN'S OPENING IS NOT THE CONSTANT. The fixture CPU's `real` column is 1
    /// on every laid row, so an UNBLINDED table's opening at ANY point is 1 — the leak committed_air's blinding exists to
    /// close (a production carrier's amount, opened in the clear). On this engine the row opened at the zerocheck's point
    /// mixes the blinding half, so it is not 1. This pin measures one column of one table; the mechanism is the same
    /// `blind_cols` + selector for every table of both rounds.
    #[test]
    fn a_blinded_constant_columns_opening_is_not_the_constant() {
        let (t, buses) = fetch_tables(None);
        assert!(t[0][CPU_REAL].iter().all(|&v| v == Fa4::ONE), "CALIBRATION: the column is the constant 1 on every laid row");
        let p = prove_postcommit_bus_bytes(t, gates, &buses, &BIND).expect("proves");
        let b: PostCommitBusBundle = postcard::from_bytes(&p).expect("decodes");
        let opened = b.round1.zcs[0].opened[CPU_REAL];
        assert_ne!(opened, Ea4::ONE, "⛔ §BE-1 LEAK: a constant column opened to the constant itself");
        eprintln!("[postcommit-bus] a constant column, blinded, opens to a value that is not the constant");
    }

    /// ⛔ A STATEMENT PAST THE COMMITMENT'S ARITY IS REFUSED, NEVER A PANIC. `WhirConfig::new` asserts the two-adicity
    /// bound, and on the verify path a round's shapes are the statement's. Table 0's laid arity is raised to
    /// [`BUS_MAX_NVARS`] (2^25 rows once blinded), a shape the gate admits but the PCS cannot; the bus shapes follow it, so
    /// the carrier reaches `LightCommitVerifier::begin`, which must refuse it.
    #[test]
    fn a_statement_past_the_commitments_arity_is_refused_without_a_panic() {
        let (t, buses) = fetch_tables(None);
        let p = prove_postcommit_bus_bytes(t, gates, &buses, &BIND).expect("proves");
        let mut b: PostCommitBusBundle = postcard::from_bytes(&p).expect("decodes");
        b.round1.shapes[0].0 = BUS_MAX_NVARS;
        let laid2 = bus_table_shapes(&b.round1.shapes, &buses).expect("the spec describes the raised shapes");
        b.round2.shapes = laid2.clone();
        let s1 = b.round1.shapes.clone();
        let bytes = postcard::to_allocvec(&b).expect("re-encodes");
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_postcommit_bus_bytes(&bytes, gates, &buses, &BIND, &s1, &laid2)
        }));
        assert!(matches!(verdict, Ok(false)), "⛔ a statement past the PCS's arity must be REFUSED, not panic: {verdict:?}");
    }
}

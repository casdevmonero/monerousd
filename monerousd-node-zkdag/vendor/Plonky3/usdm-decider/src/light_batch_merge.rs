// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ R4 lever 4 — SEVERAL LIGHT-DECIDER STATEMENTS PROVED AS ONE BATCH.
//!
//! A block carries three light-decider proofs (the note, tag and member ledgers), each with its own two WHIR rounds.
//! MEASURED 2026-11-02 (`block_wire_budget_tests::r4_a_real_ledger_block…`, main @ f837f6a): 372,608 + 433,223 + 454,167 B
//! of a 1,379,520 B block, and inside one of them (`member_ledger::tests::r4_the_member_ledger_proof_prints_its_bytes_by_part`)
//! the WHIR rounds are ~250 KB. `whir_rec_block::prove_air_batch_light_decider_selfcontained_bytes_with_bus` already proves
//! ANY number of tables in one transcript, so the three statements can share one round-1 and one round-2 opening —
//! one statement's WHIR cost instead of three.
//!
//! This module is the merge, and only the merge: each statement keeps its own tables, constraints, buses, ties and public
//! bind; the merge lays them side by side and renames every index into the joined batch —
//!   * a constraint table `t` of statement `s` → `off_c[s] + t`;
//!   * a bus table (index `n_c[s] + b` inside its statement) → `Σ n_c + off_b[s] + b` (the engine numbers every bus
//!     table after every constraint table);
//!   * a public-bind endpoint (`PUBLIC_BIND_TABLE`) keeps the sentinel and its columns move by `off_bind[s]` (the joined
//!     bind is the statements' binds in order);
//!   * the constraint for joined table `t` is statement `s`'s own constraint for its own `t − off_c[s]`.
//!
//! SOUNDNESS: the joined batch states the CONJUNCTION — every statement's constraints on its own tables, every tie
//! between its own cells, every bus balanced over its own rows, all bound to one transcript that absorbed every
//! statement's public bind before any challenge. Nothing of one statement is read by another's constraint (each
//! constraint is handed only its own table index), so no statement can be satisfied by another's witness. The verify
//! side builds the same renaming from the verifier's OWN statements (never from the proof), so a proof laid for another
//! split, order or bind fails the engine's shape and bind checks.
//! ⭐ A JOINT TIE (2026-11-03) is the one thing that crosses statements: a column tie whose first endpoint lies in an earlier
//! statement ([`JointTie`]). The tag ledger uses it to state its tags ARE the note ledger's published tags, row by row.
//! cons: none on bytes or soundness; the prover holds the three statements' tables at once (they were held one after
//! another), so the per-block prove's peak RAM is the sum of the three (MEASURED at the landing of its caller).

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::whir_rec_block::{ColumnTieSpec, CrossTieSpec, PUBLIC_BIND_TABLE};

/// The most statements one batch joins (a block's three ledgers). Each keeps its own [`crate::whir_rec_block::COLUMN_TIES_MAX`];
/// the engine's batch cap is their product ([`crate::whir_rec_block::JOINED_COLUMN_TIES_MAX`]).
pub const STATEMENTS_MAX: usize = 3;

/// One statement's constraint for one of its tables, behind a box so statements of different constraint types join.
pub type BoxedConstraint<'a> = Box<dyn AirConstraint + Sync + 'a>;
/// One statement's constraint factory: its own table index → its constraint.
pub type MakeConstraint<'a> = Box<dyn Fn(usize, Ea4) -> BoxedConstraint<'a> + 'a>;
/// A bus as the engine takes it: `(index column, value columns, multiplicity column)`.
pub type Bus = (Vec<Fa4>, Vec<Vec<Fa4>>, Vec<Fa4>);

impl AirConstraint for BoxedConstraint<'_> {
    fn degree(&self, nvars: usize) -> usize {
        (**self).degree(nvars)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        (**self).eval(local, at, x)
    }
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        (**self).residuals(local, at, x)
    }
    fn has_base_eval(&self) -> bool {
        (**self).has_base_eval()
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        (**self).eval_base(local, at, x)
    }
    fn free_columns(&self) -> Option<Vec<usize>> {
        (**self).free_columns()
    }
    fn is_row_local(&self) -> bool {
        (**self).is_row_local()
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        (**self).shifted_cols()
    }
}

/// A column tie between two statements of one batch: the spec's FIRST endpoint is in statement `.0` (an earlier one, by its
/// position in the batch), its SECOND in the statement that declares the tie. Both sides derive it from constants.
pub type JointTie = (usize, ColumnTieSpec);

/// What one statement brings to a joined PROVE.
pub struct LaidStatement<'a> {
    pub tables: Vec<Vec<Vec<Fa4>>>,
    pub make: MakeConstraint<'a>,
    pub buses: Vec<Bus>,
    pub cross: Vec<CrossTieSpec>,
    pub cols: Vec<ColumnTieSpec>,
    pub joint: Vec<JointTie>,
    pub bind: Vec<Fa4>,
}

/// What one statement brings to a joined VERIFY — every field derived by the verifier from its own inputs.
pub struct StatedStatement<'a> {
    pub make: MakeConstraint<'a>,
    pub cross: Vec<CrossTieSpec>,
    pub cols: Vec<ColumnTieSpec>,
    pub joint: Vec<JointTie>,
    pub bind: Vec<Fa4>,
    pub constraint_shapes: Vec<(usize, usize)>,
    pub bus_shapes: Vec<(usize, usize)>,
}

/// The renaming of statement `s`'s indices into the joined batch.
#[derive(Clone, Debug)]
struct Offsets {
    n_c: Vec<usize>,
    off_c: Vec<usize>,
    off_b: Vec<usize>,
    off_bind: Vec<usize>,
    total_c: usize,
}

impl Offsets {
    fn of(counts: &[(usize, usize, usize)]) -> Self {
        let (mut off_c, mut off_b, mut off_bind) = (Vec::new(), Vec::new(), Vec::new());
        let (mut c, mut b, mut p) = (0usize, 0usize, 0usize);
        for &(nc, nb, np) in counts {
            off_c.push(c);
            off_b.push(b);
            off_bind.push(p);
            c += nc;
            b += nb;
            p += np;
        }
        Offsets { n_c: counts.iter().map(|x| x.0).collect(), off_c, off_b, off_bind, total_c: c }
    }

    /// Statement `s`'s table index `t` (constraint, bus or the public-bind sentinel) in the joined batch.
    fn table(&self, s: usize, t: usize) -> usize {
        if t == PUBLIC_BIND_TABLE {
            PUBLIC_BIND_TABLE
        } else if t < self.n_c[s] {
            self.off_c[s] + t
        } else {
            self.total_c + self.off_b[s] + (t - self.n_c[s])
        }
    }

    /// Statement `s`'s columns at table `t` in the joined batch: a public-bind endpoint's columns index the joined bind.
    fn cols(&self, s: usize, t: usize, cols: &[usize]) -> Vec<usize> {
        if t == PUBLIC_BIND_TABLE {
            cols.iter().map(|c| c + self.off_bind[s]).collect()
        } else {
            cols.to_vec()
        }
    }

    fn cross(&self, s: usize, ties: &[CrossTieSpec]) -> Vec<CrossTieSpec> {
        ties.iter()
            .map(|((t1, c1, r1), (t2, c2, r2))| {
                ((self.table(s, *t1), self.cols(s, *t1, c1), *r1), (self.table(s, *t2), self.cols(s, *t2, c2), *r2))
            })
            .collect()
    }

    fn column(&self, s: usize, ties: &[ColumnTieSpec]) -> Vec<ColumnTieSpec> {
        ties.iter()
            .map(|((t1, c1, b1, r1), (t2, c2, b2, r2))| {
                (
                    (self.table(s, *t1), self.cols(s, *t1, c1), *b1, *r1),
                    (self.table(s, *t2), self.cols(s, *t2, c2), *b2, *r2),
                )
            })
            .collect()
    }

    /// Statement `s`'s joint ties in the joined batch. `None` when a tie names a statement that is not an earlier one: a batch
    /// without its partner states nothing about the tie, so it fails closed.
    fn joint(&self, s: usize, ties: &[JointTie]) -> Option<Vec<ColumnTieSpec>> {
        ties.iter()
            .map(|(from, ((t1, c1, b1, r1), (t2, c2, b2, r2)))| {
                (*from < s).then(|| {
                    (
                        (self.table(*from, *t1), self.cols(*from, *t1, c1), *b1, *r1),
                        (self.table(s, *t2), self.cols(s, *t2, c2), *b2, *r2),
                    )
                })
            })
            .collect()
    }

    /// The statement owning joined constraint table `t`, and its own index for it.
    fn owner(&self, t: usize) -> Option<(usize, usize)> {
        (0..self.n_c.len()).find(|&s| t >= self.off_c[s] && t < self.off_c[s] + self.n_c[s]).map(|s| (s, t - self.off_c[s]))
    }
}

/// The constraint for a joined table no statement laid: it never holds, so a batch that asks for one fails closed.
struct Unlaid;

impl AirConstraint for Unlaid {
    fn degree(&self, _nvars: usize) -> usize {
        1
    }
    fn eval(&self, _local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        <Ea4 as p3_field::PrimeCharacteristicRing>::ONE
    }
}

/// The joined constraint factory over the statements' own factories.
fn joined_make<'a>(off: Offsets, makes: Vec<MakeConstraint<'a>>) -> impl Fn(usize, Ea4) -> BoxedConstraint<'a> + 'a {
    move |t: usize, e: Ea4| -> BoxedConstraint<'a> {
        match off.owner(t) {
            Some((s, own)) => (makes[s])(own, e),
            None => Box::new(Unlaid),
        }
    }
}

/// PROVE the statements as one light-decider batch. `None` on an empty list or when the engine refuses.
#[must_use]
pub fn prove_joined(statements: Vec<LaidStatement<'_>>) -> Option<Vec<u8>> {
    if statements.is_empty()
        || statements.len() > STATEMENTS_MAX
        || statements.iter().any(|s| s.cols.len() > crate::whir_rec_block::COLUMN_TIES_MAX)
    {
        return None;
    }
    let off = Offsets::of(&statements.iter().map(|s| (s.tables.len(), s.buses.len(), s.bind.len())).collect::<Vec<_>>());
    let (mut tables, mut buses, mut cross, mut cols, mut bind, mut makes) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (s, st) in statements.into_iter().enumerate() {
        cross.extend(off.cross(s, &st.cross));
        cols.extend(off.column(s, &st.cols));
        cols.extend(off.joint(s, &st.joint)?);
        tables.extend(st.tables);
        buses.extend(st.buses);
        bind.extend(st.bind);
        makes.push(st.make);
    }
    let mut pch = joined_challenger(&bind);
    crate::whir_rec_block::prove_air_batch_light_decider_bytes_with_bus(
        tables,
        joined_make(off, makes),
        buses,
        cross,
        cols,
        crate::whir_rec_block::REC_DECIDER_FOLDING,
        &mut pch,
        &bind,
    )
}

/// ⭐ V2 (b) (speed5, 2026-11-16, spec LEVEL-AGGREGATE §15.5) — THE BLOCK LEDGER'S TRANSCRIPT RUNS ON THE COMMITTED DOORS'
/// PERMUTATION (`committed_air::door_challenger`, Poseidon2-16 under `COMMITTED_AIR_SEED`), then observes the joined bind.
/// WHY: the tree (`usdm_agg`) verifies this proof in circuit, and its SSA row carries ONE permutation, that one (ssa.rs
/// `SEED`); the Merkle hashing of the light rounds already is it (MEASURED: `ledger_ssa_light_round_verifies_on_the_ssa_row`
/// verifies a real round's paths). The self-contained light decider's `REC_DECIDER_SEED` permutation is not on the row, so
/// the ledger's Fiat–Shamir could not be replayed in circuit. Either fixed public Poseidon2 instance is a Fiat–Shamir
/// permutation of the same strength; ONE for everything the tree verifies is the borrowed shape (Mina: one sponge for the
/// recursive verifier). The prover and the verifier build it here, at one site, so they cannot disagree.
/// FORMAT: the joined proof's transcript changes; every node rebuilds and rigs start from genesis.
fn joined_challenger(bind: &[Fa4]) -> crate::hiding_decider::Chl {
    use p3_challenger::CanObserve;
    let mut ch = crate::committed_air::door_challenger();
    for &f in bind {
        ch.observe(f);
    }
    ch
}

/// VERIFY one joined proof against the verifier's own statements, in the order the prover joined them.
#[must_use]
pub fn verify_joined(bytes: &[u8], statements: Vec<StatedStatement<'_>>) -> bool {
    if statements.is_empty()
        || statements.len() > STATEMENTS_MAX
        || statements.iter().any(|s| s.cols.len() > crate::whir_rec_block::COLUMN_TIES_MAX)
    {
        return false;
    }
    let off = Offsets::of(
        &statements.iter().map(|s| (s.constraint_shapes.len(), s.bus_shapes.len(), s.bind.len())).collect::<Vec<_>>(),
    );
    let (mut cross, mut cols, mut bind, mut makes, mut shapes, mut bus_shapes) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (s, st) in statements.into_iter().enumerate() {
        cross.extend(off.cross(s, &st.cross));
        cols.extend(off.column(s, &st.cols));
        let Some(joint) = off.joint(s, &st.joint) else { return false };
        cols.extend(joint);
        bind.extend(st.bind);
        shapes.extend(st.constraint_shapes);
        bus_shapes.extend(st.bus_shapes);
        makes.push(st.make);
    }
    let mut vch = joined_challenger(&bind);
    crate::whir_rec_block::verify_air_batch_light_decider_bytes_with_bus(
        bytes,
        joined_make(off, makes),
        cross,
        cols,
        &mut vch,
        &bind,
        &shapes,
        &bus_shapes,
    )
}

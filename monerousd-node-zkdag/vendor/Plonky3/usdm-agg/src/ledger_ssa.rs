// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ V2 (b) — THE BLOCK'S JOINED LEDGER PROOF, VERIFIED ON THE SSA BUILDER (docs/LEVEL-AGGREGATE-SPEC-20261115.md §15.5).
//!
//! The ledger proof is a light-decider BATCH (`usdm_decider::whir_rec_block::verify_air_batch_light_decider_bytes_with_bus`):
//! several tables in ONE stacked commitment per round, opened by one WHIR proof. The tree's carrier door (`door_ssa`)
//! opens a single table; this module adds what a batch needs, one piece at a time, each pinned against the native code.
//!
//! PIECE 1 (this commit) — THE STACKED CLOSING WEIGHT. The WHIR opening of a stacked round checks its claims against one
//! weight polynomial: `W(x) = Σ_j α^j · eq(lifted_j, x) + Σ_i α^(nc+i) · eq(expand(y_i, k), x)`, where claim `j` is one
//! opened column of one table at one point, `lifted_j` is that point lifted into the table's stacked arity and joined with
//! the column's SELECTOR bits, and the sum runs in the native verifier's PLACEMENT order (largest table first), not table
//! order (`p3_sumcheck::layout::Verifier::constraint`). The selector of every column is read from the native verifier's own
//! plan (`Verifier::placements`), never recomputed here, so the two cannot drift.
//!
//! AI RESISTANT: (a) — a weight that differs from the native one at any point fails the WHIR closing check; the pin
//! `ledger_ssa_stacked_weight_is_the_native_constraint` demands equality at every point of the hypercube (both sides are
//! multilinear in `x`, so that is equality everywhere) and that one moved selector disagrees.
//! SCALE: rows ∝ (opened columns × selector bits) + claims × arity; a constant for a block's ledger shape. cons: none at run
//! time (no consensus path reads this module yet).

use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::layout::Verifier as LayoutVerifier;
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::ssa::{Builder, Ext};

/// One claim the batch verifier adds to a stacked round: columns `cols` of table `table` opened at `point` (the table's own
/// variables, before lifting).
pub struct StackedClaim {
    pub table: usize,
    pub cols: Vec<usize>,
    pub point: Vec<Ext>,
}

/// `eq(a, c)` for one coordinate.
fn eq1(b: &mut Builder, a: Ext, c: Ext) -> Ext {
    // a·c + (1 − a)(1 − c) = 1 − a − c + 2ac
    let ac = b.mul(a, c);
    let two_ac = b.add(ac, ac);
    let s = b.add(a, c);
    let t = b.sub(Ext::ONE, s);
    b.add(t, two_ac)
}

/// `eq` of a CONSTANT bit with one coordinate: `c` for a 1, `1 − c` for a 0.
fn eq_bit(b: &mut Builder, bit: bool, c: Ext) -> Ext {
    if bit {
        c
    } else {
        b.sub(Ext::ONE, c)
    }
}

/// The stacked round's closing weight at `x` (k coordinates, the native constraint's own variable order), for `claims` in
/// the order the native verifier added them and the out-of-domain points `oods` (the `y`s of `add_virtual_eval`, in order).
/// `lv` is the native verifier built for the round's shapes (its plan: `k`, every column's selector); `nvars[t]` is table
/// `t`'s own variable count and `arity(nvars)` its stacked arity (`light_commit`'s padding, leading zeros).
pub fn emit_stacked_weight(
    b: &mut Builder,
    lv: &LayoutVerifier<Fa4, Ea4>,
    nvars: &[usize],
    arity: &dyn Fn(usize) -> usize,
    claims: &[StackedClaim],
    oods: &[Ext],
    alpha: Ext,
    x: &[Ext],
) -> Result<Ext, String> {
    let k = lv.num_variables();
    if x.len() != k {
        return Err(format!("the weight is read at {} coordinates, the stacked round has {k}", x.len()));
    }
    let suffix = lv.reverses_selectors();
    let mut acc = Ext::ZERO;
    let mut apow = Ext::ONE;
    for placement in lv.placements() {
        let t = placement.idx();
        let nv = *nvars.get(t).ok_or("a placement names a table the round does not have")?;
        let ar = arity(nv);
        if ar < nv {
            return Err("a table's stacked arity is below its own variable count".into());
        }
        for c in claims.iter().filter(|c| c.table == t) {
            if c.point.len() != nv {
                return Err(format!("a claim on table {t} has {} coordinates, the table has {nv}", c.point.len()));
            }
            // the lifted point: `ar − nv` leading zeros, then the claim's point
            let mut lifted: Vec<Option<Ext>> = vec![None; ar - nv];
            lifted.extend(c.point.iter().map(|&p| Some(p)));
            for &col in &c.cols {
                let sel = placement.selectors().get(col).ok_or("a claim opens a column the table does not have")?;
                let sbits = sel.num_variables();
                if ar + sbits != k {
                    return Err("a column's selector and its table's arity do not fill the stacked round".into());
                }
                let bits: Vec<bool> = (0..sbits).map(|i| (sel.index() >> (sbits - 1 - i)) & 1 == 1).collect();
                // the point's half and the selector's half of x, in the native lift's order
                let (pt_x, sel_x) = if suffix { (&x[..ar], &x[ar..]) } else { (&x[sbits..], &x[..sbits]) };
                let mut e = Ext::ONE;
                for (l, &xc) in lifted.iter().zip(pt_x) {
                    let f = match l {
                        Some(p) => eq1(b, *p, xc),
                        None => b.sub(Ext::ONE, xc),
                    };
                    e = b.mul(e, f);
                }
                for (&bit, &xc) in bits.iter().zip(sel_x) {
                    let f = eq_bit(b, bit, xc);
                    e = b.mul(e, f);
                }
                acc = b.mul_add(apow, e, acc);
                apow = b.mul(apow, alpha);
            }
        }
    }
    // the out-of-domain points: expand(y, k) = [y^(2^(k−1)), …, y², y]
    for &y in oods {
        let mut pw = vec![y];
        for _ in 1..k {
            let last = *pw.last().expect("a power");
            pw.push(b.mul(last, last));
        }
        pw.reverse();
        let mut e = Ext::ONE;
        for (&p, &xc) in pw.iter().zip(x) {
            let f = eq1(b, p, xc);
            e = b.mul(e, f);
        }
        acc = b.mul_add(apow, e, acc);
        apow = b.mul(apow, alpha);
    }
    let _ = Ea4::ZERO;
    Ok(acc)
}

/// The arity a table has INSIDE a light round's stacked witness (`light_commit::stacked_arity`: zero-padded below the first
/// fold, the padding variables leading).
#[must_use]
pub fn light_arity(nvars: usize) -> usize {
    nvars.max(usdm_decider::light_commit::LIGHT_COMMIT_PARAMS.first_fold)
}

/// PIECE 2 — ONE LIGHT ROUND (`light_commit::LightCommitVerifier`) ON THE SSA BUILDER, step for step: `begin` observes the
/// root and replays the out-of-domain answers (`y` drawn, the answer absorbed), `add_claim_at` absorbs a claim's values,
/// `finish` draws α, forms the batched claim `Σ α^j·v_j` in the native constraint's order (placement order, then insertion
/// order inside a table, then the virtual claims) and runs the WHIR opening against the root with the stacked weight of
/// piece 1 as its initial constraint. Every check the native round makes is an assertion here.
///
/// §9.6 — a verifier program for an existing door's object, not a new door: (1)–(6) are the native round's, unchanged; (7)
/// scale: rows ∝ the WHIR schedule of the stacked arity + (claims × arity), a constant for a ledger shape; (8) (a).
pub struct LightRoundSsa {
    lv: LayoutVerifier<Fa4, Ea4>,
    cfg: crate::verify_whir::CarrierWhirConfig,
    nvars: Vec<usize>,
    root: [crate::ssa::Addr; crate::ssa::RATE],
    oods: Vec<(Ext, Ext)>,
    claims: Vec<(StackedClaim, Vec<Ext>)>,
    open: Option<crate::verify_whir::CarrierWhirProof>,
}

impl LightRoundSsa {
    /// `shapes` are `(nvars, width)` as the statement pins them; `round = None` lays the same program over zeros.
    pub fn begin(b: &mut Builder, ch: &mut crate::ssa::Chal, shapes: &[(usize, usize)], round: Option<&usdm_decider::light_commit::LightRound>) -> Result<Self, String> {
        use p3_sumcheck::layout::{Layout, PrefixProver, TableShape};
        if shapes.is_empty() || shapes.iter().any(|&(nv, w)| w == 0 || nv > usdm_decider::committed_air::MAX_STATEABLE_NVARS) {
            return Err("a light round of no table, an empty table or a table past the stateable arity".into());
        }
        let table_shapes: Vec<TableShape> = shapes.iter().map(|&(nv, w)| TableShape::new(light_arity(nv), w)).collect();
        let lv = LayoutVerifier::<Fa4, Ea4>::new(&table_shapes, PrefixProver::<Fa4, Ea4>::strategy());
        if !usdm_decider::light_commit::light_arity_admissible(lv.num_variables()) {
            return Err("the stacked arity is past the PCS's two-adicity".into());
        }
        let cfg = usdm_decider::committed_air::door_pcs(lv.num_variables(), usdm_decider::light_commit::light_params(lv.num_variables())).config;
        let n_ood = cfg.commitment_ood_samples;
        let (rootw, answers, open) = match round {
            None => ([Fa4::ZERO; crate::ssa::RATE], vec![Ea4::ZERO; n_ood], None),
            Some(r) => {
                if !r.open.hvzk_mask_commits.is_empty() || r.open.initial_ood_answers.len() != n_ood {
                    return Err("the round carries a mask commitment or the wrong number of out-of-domain answers".into());
                }
                let cap: &[[Fa4; crate::ssa::RATE]] = r.commitment.as_ref();
                if cap.len() != 1 {
                    return Err("a commitment cap of more than one root".into());
                }
                (cap[0], r.open.initial_ood_answers.clone(), Some(r.open.clone()))
            }
        };
        let rv = b.load(&rootw);
        let root: [crate::ssa::Addr; crate::ssa::RATE] = rv[..].try_into().map_err(|_| "eight root words")?;
        ch.observe_all(b, &root);
        let mut oods = Vec::with_capacity(n_ood);
        for e in answers {
            let y = ch.sample_ext(b);
            let a = b.load_ext(e);
            ch.observe_ext(b, a);
            oods.push((y, a));
        }
        Ok(Self { lv, cfg, nvars: shapes.iter().map(|&(nv, _)| nv).collect(), root, oods, claims: Vec::new(), open })
    }

    /// Record `cols` of table `table` at `point` (the table's own arity) `= vals`; absorbs `vals`.
    pub fn add_claim_at(&mut self, b: &mut Builder, ch: &mut crate::ssa::Chal, table: usize, cols: &[usize], vals: &[Ext], point: &[Ext]) -> Result<(), String> {
        let nv = *self.nvars.get(table).ok_or("a claim on a table the round does not have")?;
        if cols.is_empty() || cols.len() != vals.len() || point.len() != nv {
            return Err("a claim's columns, values or point do not match its table".into());
        }
        for v in vals {
            ch.observe_ext(b, *v);
        }
        self.claims.push((StackedClaim { table, cols: cols.to_vec(), point: point.to_vec() }, vals.to_vec()));
        Ok(())
    }

    /// α, the batched claim and the WHIR opening.
    pub fn finish(self, b: &mut Builder, ch: &mut crate::ssa::Chal, whir: &mut dyn crate::door_ssa::WhirSsa) -> Result<(), String> {
        let Self { lv, cfg, nvars, root, oods, claims, open } = self;
        let alpha = ch.sample_ext(b);
        // the native constraint's order: placements (largest table first), insertion order inside a table, then columns
        let mut all: Vec<Ext> = Vec::new();
        for placement in lv.placements() {
            for (_, vals) in claims.iter().filter(|(c, _)| c.table == placement.idx()) {
                all.extend_from_slice(vals);
            }
        }
        if all.len() != claims.iter().map(|(_, v)| v.len()).sum::<usize>() {
            return Err("a claim names a table no placement holds".into());
        }
        all.extend(oods.iter().map(|p| p.1));
        let claimed = crate::door_ssa::horner(b, &all, alpha);
        let stacked: Vec<StackedClaim> = claims.into_iter().map(|(c, _)| c).collect();
        let ys: Vec<Ext> = oods.iter().map(|p| p.0).collect();
        let mut err: Option<String> = None;
        let mut init = |b: &mut Builder, coords: &[Ext]| -> Ext {
            match emit_stacked_weight(b, &lv, &nvars, &light_arity, &stacked, &ys, alpha, coords) {
                Ok(w) => w,
                Err(e) => {
                    err.get_or_insert(e);
                    Ext::ZERO
                }
            }
        };
        let base = b.phase.clone();
        b.phase = format!("{base} / light round whir");
        let r = whir.emit(b, ch, &cfg, open.as_ref(), root, claimed, &mut init);
        b.phase = base;
        r?;
        err.map_or(Ok(()), Err)
    }
}

/// The tree ledger proof's values, or zeros of the statement's shapes (`bytes = None` lays the same program).
struct LedgerData {
    zcs: Vec<(Vec<Vec<Ea4>>, Vec<Ea4>, Vec<Ea4>)>, // per table: round evals, opened, shifted opened
    binds: Vec<(Vec<Vec<Ea4>>, Vec<Ea4>)>,         // per table with a next-row set: bind rounds, bind opened
    cross: Vec<(Vec<Ea4>, Vec<Ea4>)>,
    cols: Vec<(Vec<Ea4>, Vec<Ea4>)>,
    round: Option<usdm_decider::light_commit::LightRound>,
}

fn ledger_data(plan: &usdm_decider::tree_ledger::TreeLedgerPlan, bytes: Option<&[u8]>) -> Result<LedgerData, String> {
    use usdm_decider::whir_rec_block::PUBLIC_BIND_TABLE;
    let z = |n: usize| vec![Ea4::ZERO; n];
    let shaped = LedgerData {
        zcs: plan.shapes.iter().zip(&plan.sets).zip(&plan.degrees).map(|((&(nv, w), s), &d)| (vec![z(d + 2); nv], z(w), z(s.len()))).collect(),
        binds: plan.shapes.iter().zip(&plan.sets).filter(|(_, s)| !s.is_empty()).map(|(&(nv, _), s)| (vec![z(3); nv], z(s.len()))).collect(),
        cross: plan.cross.iter().map(|((t1, c1, _), (t2, c2, _))| {
            (if *t1 == PUBLIC_BIND_TABLE { Vec::new() } else { z(c1.len()) }, if *t2 == PUBLIC_BIND_TABLE { Vec::new() } else { z(c2.len()) })
        }).collect(),
        cols: plan.cols.iter().map(|(e1, e2)| (z(e1.1.len()), z(e2.1.len()))).collect(),
        round: None,
    };
    let Some(bytes) = bytes else { return Ok(shaped) };
    let bb: usdm_decider::whir_rec_block::AirBatchBusBundle = postcard::from_bytes(bytes).map_err(|e| format!("the ledger proof does not decode: {e}"))?;
    if bb.n_constraint != plan.shapes.len() || bb.shapes != plan.shapes || !bb.tied_buses.is_empty() || bb.round2.is_some() || bb.zcs.len() != plan.shapes.len() {
        return Err("the ledger proof is not this statement's shape".into());
    }
    let d = LedgerData {
        zcs: bb.zcs.iter().map(|zc| (zc.round_evals.clone(), zc.opened.clone(), zc.shifted_opened.clone())).collect(),
        binds: bb.shift_binds.iter().map(|sb| (sb.round_evals.clone(), sb.opened.clone())).collect(),
        cross: bb.cross_tie_openings.clone(),
        cols: bb.column_tie_openings.clone(),
        round: Some(bb.round1),
    };
    // every length the program lays must be the proof's: one encoding, and no value left for the program to guess
    let same = |a: &[Vec<Ea4>], b: &[Vec<Ea4>]| a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.len() == y.len());
    let ok = d.zcs.len() == shaped.zcs.len()
        && d.zcs.iter().zip(&shaped.zcs).all(|(a, b)| same(&a.0, &b.0) && a.1.len() == b.1.len() && a.2.len() == b.2.len())
        && d.binds.len() == shaped.binds.len()
        && d.binds.iter().zip(&shaped.binds).all(|(a, b)| same(&a.0, &b.0) && a.1.len() == b.1.len())
        && d.cross.len() == shaped.cross.len()
        && d.cross.iter().zip(&shaped.cross).all(|(a, b)| a.0.len() == b.0.len() && a.1.len() == b.1.len())
        && d.cols.len() == shaped.cols.len()
        && d.cols.iter().zip(&shaped.cols).all(|(a, b)| a.0.len() == b.0.len() && a.1.len() == b.1.len());
    if !ok {
        return Err("the ledger proof's lengths are not this statement's".into());
    }
    Ok(d)
}

/// A boolean point's coordinates as constants (`whir_rec_block::boolean_point` / `segment_point`'s low bits: MSB first).
fn bits_of(row: usize, n: usize) -> Vec<Ext> {
    (0..n).map(|k| if (row >> (n - 1 - k)) & 1 == 1 { Ext::ONE } else { Ext::ZERO }).collect()
}

/// ⭐ V2 (b) PIECE 3 — THE BLOCK'S TREE LEDGER PROOF VERIFIED ON THE SSA BUILDER: `light_batch_merge::verify_joined` of the
/// one tree-ledger statement (`whir_rec_block::verify_air_batch_light_decider_bytes_with_bus`, no buses), step for step —
/// the transcript (the joined challenger, then the public bind), round 1's commitment, γ; per table z, the zerocheck's
/// rounds and its closing check against the table's gate evaluated in circuit (`gate_trace::tree_ledger_step_program`,
/// `sponge_chain_program`), the opened row's claim, the next-row openings and the shift bind; the cross ties (a committed
/// cell equals the bind's own value) and the column ties (two committed segments agree at one shared point); then the
/// round's WHIR opening ([`LightRoundSsa::finish`]). `bind` are the statement's public addresses in the bind's order;
/// `step_publics` the step gate's (seed commitment lanes, then the clock constant), `chain_publics` the chain's expected
/// fold. Every check the native verifier makes is an assertion here (a read of `ZERO`), so a proof the node refuses has no
/// satisfying trace. AI RESISTANT: (a). SCALE: a constant per ledger shape (MEASURED 2^15 rows for the round alone).
#[allow(clippy::too_many_arguments)]
pub fn emit_tree_ledger_door(
    b: &mut Builder,
    plan: &usdm_decider::tree_ledger::TreeLedgerPlan,
    bind: &[crate::ssa::Addr],
    step_publics: &[Ext],
    chain_publics: &[Ext],
    bytes: Option<&[u8]>,
    whir: &mut dyn crate::door_ssa::WhirSsa,
) -> Result<(), String> {
    use crate::door_ssa::{eq_ext, horner, lagrange, shift_mle};
    use usdm_decider::tree_ledger::{TL_CHAIN, TL_STEP};
    use usdm_decider::whir_rec_block::PUBLIC_BIND_TABLE;
    if plan.shapes.len() != 2 {
        return Err("the tree ledger states two tables".into());
    }
    let data = ledger_data(plan, bytes)?;
    // the two gates as programs, built from the statement
    let (step_prog, step_lay) = usdm_decider::gate_trace::tree_ledger_step_program(plan.shapes[TL_STEP].0).ok_or("the step gate does not trace")?;
    let cc = usdm_decider::sponge_chain_air::make_constraint_with_seed(usdm_decider::committed_air::COMMITTED_AIR_SEED, Fa4::ZERO)(Ea4::ZERO);
    let (chain_prog, chain_lay) =
        usdm_decider::gate_trace::sponge_chain_program(&cc, plan.shapes[TL_CHAIN].1, plan.shapes[TL_CHAIN].0).ok_or("the chain gate does not trace")?;
    if step_lay.width != plan.shapes[TL_STEP].1 || !step_lay.shifted.is_empty() || step_lay.publics != step_publics.len() {
        return Err("the step gate's layout is not the statement's".into());
    }
    if chain_lay.shifted != plan.sets[TL_CHAIN] || chain_lay.publics != chain_publics.len() || !plan.sets[TL_STEP].is_empty() {
        return Err("the chain gate's next-row set is not the statement's".into());
    }
    let progs = [(&step_prog, step_publics), (&chain_prog, chain_publics)];
    let base = b.phase.clone();
    b.phase = format!("{base} / tree ledger: commitment");
    let mut ch = crate::ssa::Chal::new();
    ch.observe_all(b, bind);
    let mut lr = LightRoundSsa::begin(b, &mut ch, &plan.shapes, data.round.as_ref())?;
    let gamma = ch.sample_ext(b);
    let mut next_bind = 0usize;
    for t in 0..plan.shapes.len() {
        b.phase = format!("{base} / tree ledger: table {t} zerocheck");
        let (nv, w) = plan.shapes[t];
        let (rounds, opened_v, next_v) = &data.zcs[t];
        let zpt: Vec<Ext> = (0..nv).map(|_| ch.sample_ext(b)).collect();
        let mut claim = Ext::ZERO;
        let mut r: Vec<Ext> = Vec::with_capacity(nv);
        for h in rounds {
            let hv: Vec<Ext> = h.iter().map(|v| b.load_ext(*v)).collect();
            let s = b.add(hv[0], hv[1]);
            b.assert_eq(s, claim);
            for e in &hv {
                ch.observe_ext(b, *e);
            }
            let rk = ch.sample_ext(b);
            claim = lagrange(b, &hv, rk);
            r.push(rk);
        }
        let opened: Vec<Ext> = opened_v.iter().map(|v| b.load_ext(*v)).collect();
        let next: Vec<Ext> = next_v.iter().map(|v| b.load_ext(*v)).collect();
        let (prog, pubs) = progs[t];
        let mut inputs = opened.clone();
        inputs.extend_from_slice(&next);
        inputs.extend_from_slice(&r);
        inputs.extend_from_slice(pubs);
        let cg = crate::gate_ssa::emit_gate(b, prog, &inputs, gamma)?;
        let e = eq_ext(b, &zpt, &r);
        let ec = b.mul(e, cg);
        b.assert_eq(ec, claim);
        let all: Vec<usize> = (0..w).collect();
        lr.add_claim_at(b, &mut ch, t, &all, &opened, &r)?;
        for v in &next {
            ch.observe_ext(b, *v);
        }
        if !plan.sets[t].is_empty() {
            b.phase = format!("{base} / tree ledger: table {t} shift bind");
            let (brounds, bopened) = data.binds.get(next_bind).ok_or("a shift bind is missing")?;
            next_bind += 1;
            let lambda = ch.sample_ext(b);
            let mut cb = horner(b, &next, lambda);
            let mut rho: Vec<Ext> = Vec::with_capacity(nv);
            for h in brounds {
                let hv: Vec<Ext> = h.iter().map(|v| b.load_ext(*v)).collect();
                let s = b.add(hv[0], hv[1]);
                b.assert_eq(s, cb);
                for e in &hv {
                    ch.observe_ext(b, *e);
                }
                let c = ch.sample_ext(b);
                cb = lagrange(b, &hv, c);
                rho.push(c);
            }
            let bo: Vec<Ext> = bopened.iter().map(|v| b.load_ext(*v)).collect();
            lr.add_claim_at(b, &mut ch, t, &plan.sets[t], &bo, &rho)?;
            let sh = shift_mle(b, &r, &rho);
            let lf = horner(b, &bo, lambda);
            let want = b.mul(sh, lf);
            b.assert_eq(cb, want);
        }
    }
    if next_bind != data.binds.len() {
        return Err("the proof carries a shift bind no table reads".into());
    }
    b.phase = format!("{base} / tree ledger: ties");
    for (i, ((t1, c1, row1), (t2, c2, row2))) in plan.cross.iter().enumerate() {
        let (cv1, cv2) = &data.cross[i];
        let mut end = |b: &mut Builder, ch: &mut crate::ssa::Chal, lr: &mut LightRoundSsa, t: usize, cs: &[usize], row: usize, cv: &[Ea4]| -> Result<Vec<Ext>, String> {
            if t == PUBLIC_BIND_TABLE {
                return cs.iter().map(|&j| bind.get(j).map(|&a| Ext([a, crate::ssa::ZERO, crate::ssa::ZERO, crate::ssa::ZERO]))).collect::<Option<Vec<Ext>>>().ok_or_else(|| "a cross tie names a bind cell past the bind".to_string());
            }
            let nvt = plan.shapes.get(t).ok_or("a cross tie names a table the statement does not have")?.0;
            let v: Vec<Ext> = cv.iter().map(|x| b.load_ext(*x)).collect();
            lr.add_claim_at(b, ch, t, cs, &v, &bits_of(row, nvt))?;
            Ok(v)
        };
        let a = end(b, &mut ch, &mut lr, *t1, c1, *row1, cv1)?;
        let c = end(b, &mut ch, &mut lr, *t2, c2, *row2, cv2)?;
        for (x, y) in a.iter().zip(&c) {
            b.assert_eq(*x, *y);
        }
    }
    for (i, (e1, e2)) in plan.cols.iter().enumerate() {
        let n1 = plan.shapes.get(e1.0).and_then(|s| s.0.checked_sub(e1.2)).ok_or("a column tie past its table")?;
        let n2 = plan.shapes.get(e2.0).and_then(|s| s.0.checked_sub(e2.2)).ok_or("a column tie past its table")?;
        if n1 != n2 || e1.1.len() != e2.1.len() || e1.1.is_empty() {
            return Err("a column tie's endpoints do not share a point".into());
        }
        let high: Vec<Ext> = (0..n1).map(|_| ch.sample_ext(b)).collect();
        let (cv1, cv2) = &data.cols[i];
        let mut vals: Vec<Vec<Ext>> = Vec::with_capacity(2);
        for (e, cv) in [(e1, cv1), (e2, cv2)] {
            let mut pt = high.clone();
            pt.extend(bits_of(e.3, e.2));
            let v: Vec<Ext> = cv.iter().map(|x| b.load_ext(*x)).collect();
            lr.add_claim_at(b, &mut ch, e.0, &e.1, &v, &pt)?;
            vals.push(v);
        }
        for (x, y) in vals[0].iter().zip(&vals[1]) {
            b.assert_eq(*x, *y);
        }
    }
    b.phase = format!("{base} / tree ledger: opening");
    lr.finish(b, &mut ch, whir)?;
    b.phase = base;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p3_challenger::FieldChallenger;
    use p3_field::BasedVectorSpace;
    use p3_multilinear_util::point::Point;
    use p3_sumcheck::layout::{Layout, PrefixProver, TableShape};
    use rand::{RngExt, SeedableRng};

    fn rand_ea(rng: &mut rand::rngs::SmallRng) -> Ea4 {
        let lanes: [Fa4; 4] = core::array::from_fn(|_| Fa4::from_u32(rng.random::<u32>() % 2_000_000_000));
        Ea4::from_basis_coefficients_slice(&lanes).expect("four lanes")
    }

    fn challenger() -> usdm_decider::hiding_decider::Chl {
        use rand::SeedableRng as _;
        let mut r = rand::rngs::SmallRng::seed_from_u64(7);
        usdm_decider::hiding_decider::Chl::new(usdm_decider::hiding_decider::Perm16::new_from_rng_128(&mut r))
    }

    /// ⭐ PIECE 2's PIN: A REAL LIGHT ROUND (the light decider's own prover: three tables, two arities, one padded below the
    /// first fold, four claims at transcript-drawn points) verified natively AND by the SSA program — every assertion
    /// holds; the statement-only program lays the same rows; then the lies, each a failed assertion: a moved claim value,
    /// a moved out-of-domain answer, a moved WHIR leaf word.
    #[test]
    fn ledger_ssa_light_round_verifies_on_the_ssa_row() {
        use p3_challenger::FieldChallenger as _;
        use usdm_decider::light_commit::{LightCommitProver, LightCommitVerifier, LightRound};
        let mut rng = rand::rngs::SmallRng::seed_from_u64(9);
        let shapes = [(6usize, 3usize), (5, 2), (3, 1)];
        let tables: Vec<Vec<Vec<Fa4>>> = shapes
            .iter()
            .map(|&(nv, w)| (0..w).map(|_| (0..1usize << nv).map(|_| Fa4::from_u32(rng.random::<u32>() % 2_000_000_000)).collect()).collect())
            .collect();
        let plan: Vec<(usize, Vec<usize>)> = vec![(0, vec![0, 1, 2]), (1, vec![1]), (2, vec![0]), (0, vec![2])];
        // native prover
        let mut pch = usdm_decider::committed_air::door_challenger();
        let mut prover = LightCommitProver::commit(tables, &mut pch).expect("commits");
        let mut vals_native: Vec<Vec<Ea4>> = Vec::new();
        for (t, cols) in &plan {
            let pt: Vec<Ea4> = (0..shapes[*t].0).map(|_| pch.sample_algebra_element()).collect();
            vals_native.push(prover.eval_at(*t, cols, &Point::new(pt), &mut pch));
        }
        let round = prover.finish(&mut pch);
        // native verifier (calibration)
        let native_ok = |round: &LightRound, vals: &[Vec<Ea4>]| -> bool {
            let mut vch = usdm_decider::committed_air::door_challenger();
            let Some(mut v) = LightCommitVerifier::begin(&shapes, round, &mut vch) else { return false };
            for ((t, cols), vs) in plan.iter().zip(vals) {
                let pt: Vec<Ea4> = (0..shapes[*t].0).map(|_| vch.sample_algebra_element()).collect();
                v.add_claim_at(*t, cols, vs, &Point::new(pt), &mut vch);
            }
            v.finish(&mut vch)
        };
        assert!(native_ok(&round, &vals_native), "CALIBRATION: the native light round accepts its own proof");
        let build = |round: Option<&LightRound>, vals: &[Vec<Ea4>]| -> Result<Builder, String> {
            let mut b = Builder::new();
            let mut ch = crate::ssa::Chal::new();
            let mut lr = LightRoundSsa::begin(&mut b, &mut ch, &shapes, round)?;
            for ((t, cols), vs) in plan.iter().zip(vals) {
                let pt: Vec<Ext> = (0..shapes[*t].0).map(|_| ch.sample_ext(&mut b)).collect();
                let v: Vec<Ext> = vs.iter().map(|&x| b.load_ext(if round.is_some() { x } else { Ea4::ZERO })).collect();
                lr.add_claim_at(&mut b, &mut ch, *t, cols, &v, &pt)?;
            }
            lr.finish(&mut b, &mut ch, &mut crate::verify_whir_ssa::WhirOnSsa)?;
            Ok(b)
        };
        let t0 = std::time::Instant::now();
        let b = build(Some(&round), &vals_native).expect("the program builds");
        assert_eq!(b.mismatch, None, "⛔ an assertion of the SSA light round fails on an honest round");
        let vb = build(None, &vals_native).expect("the statement-only program builds");
        let (_, prog) = crate::ssa::lay(&b).expect("lays");
        let (_, vprog) = crate::ssa::lay(&vb).expect("lays");
        assert_eq!(prog.fixed, vprog.fixed, "⛔ the program depends on the proof's values");
        println!("[v2-ledger] light round of 3 tables on the SSA row: {} ops, {} rows (T = 2^{}), built in {} ms", b.ops.len(), prog.rows, prog.nvars, t0.elapsed().as_millis());
        let lie = |round: &LightRound, vals: &[Vec<Ea4>]| -> bool { build(Some(round), vals).map_or(true, |b| b.mismatch.is_some()) };
        let mut moved = vals_native.clone();
        moved[1][0] += Ea4::ONE;
        assert!(!native_ok(&round, &moved), "CALIBRATION: the native round refuses a moved claim value");
        assert!(lie(&round, &moved), "⛔ LIE: a moved claim value passed");
        let mut r2 = round.clone();
        r2.open.initial_ood_answers[0] += Ea4::ONE;
        assert!(lie(&r2, &vals_native), "⛔ LIE: a moved out-of-domain answer passed");
        let mut r3 = round.clone();
        if let Some(p3_whir::pcs::proof::QueryOpening::Base { values, .. }) = r3.open.rounds.get_mut(0).and_then(|r| r.queries.get_mut(0)) {
            values[0] += Fa4::ONE;
            assert!(lie(&r3, &vals_native), "⛔ LIE: a moved WHIR leaf word passed");
        }
    }

    /// A REAL block ledger: the tree ledger proof of a production ledger (LEDGER_ROWS rows, two real spends) and its
    /// statement (bind, seed commitment, clock 0, roots of four lanes each) — the fixture the tree's ledger node pins share.
    pub(crate) fn ledger_fixture() -> (Vec<u8>, Vec<Fa4>, usdm_decider::poseidon2_compress::Digest, usize, usize) {
        use usdm_decider::poseidon2_compress::lanes_of;
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(usdm_decider::whir_rec_block::SPEND_VALIDITY_DOMAIN);
        let s = lanes_of(&[0x5eed, 0x1ed6, 3, 4]);
        let sc = usdm_decider::slot_ledger::seed_commit_native(s);
        let pbs = spend_pbs();
        let filing = |a: &usdm_decider::poseidon2_compress::Digest, b: &usdm_decider::poseidon2_compress::Digest| {
            Some(usdm_decider::nullifier_insert_air::poseidon_pair_native(*a, *b))
        };
        let rows = usdm_decider::settlement_delta::plan_ledger_rows(s, pbs.len(), &[], &[], &filing).expect("the block is stateable");
        let (proof, published, _) = usdm_decider::tree_ledger::prove_tree_ledger(&pbs, &rows, dom, &onr, &dsr, s, 0).expect("the tree ledger proves");
        assert!(usdm_decider::tree_ledger::verify_tree_ledger(&proof, dom, &onr, &dsr, sc, &published, 0), "CALIBRATION: the node's door accepts it");
        let bind = usdm_decider::tree_ledger::tree_ledger_stated(dom, &onr, &dsr, sc, &published, 0).expect("the statement").bind;
        (proof, bind, sc, onr.len(), dsr.len())
    }

    /// Two real spend carriers' public binds (the wallet's own prover, as `settlement_delta`'s ledger pins make them).
    pub(crate) fn spend_pbs() -> Vec<Vec<Fa4>> {
        use usdm_decider::poseidon2_compress::{lanes_of, Digest, DIGEST_LANES};
        use usdm_decider::whir_rec_block as w;
        (0..2u64)
            .map(|i| {
                let sk = lanes_of(&[11 + i, 12, 13, 14]);
                let wit = w::SpendValidityWitness {
                    value_in: 800 + i + w::PROTOCOL_FEE_ATOMIC,
                    owner: w::NoteOwner::from_test_key(sk),
                    value_out: 800 + i,
                    fee: w::PROTOCOL_FEE_ATOMIC,
                    lc_blind: lanes_of(&[0x363, i, 2, 3]),
                    out0_value: 750 + i,
                    out0_opening: lanes_of(&[7, 7, 7, 7]),
                    out1_value: 50,
                    out1_opening: sk,
                };
                let clue = lanes_of(&[0xC1, 0xE5, i, 9]);
                let (_bytes, cms, nf, lc) = w::prove_spend_validity_carrier_with_commit_bytes(&wit, clue).expect("the production spend proves");
                let f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|j| Fa4::from_u64(d[j])) };
                w::validity_public_bind_with_commit(&[f(cms[0]), f(cms[1])], &f(nf), &f(lc), &f(clue), &f(w::spend_tag1(&wit)))
            })
            .collect()
    }

    /// ⭐⭐ V2 (b) PIECE 3's PIN — A REAL BLOCK LEDGER PROOF VERIFIED ON THE SSA ROW. The tree ledger proof of a production
    /// ledger (LEDGER_ROWS rows, two real spends) made by the node's own prover is verified natively AND by the SSA program
    /// (the joined challenger, round 1, both tables' zerocheck against their gates in circuit, the chain's shift bind, the
    /// cross and column ties, the WHIR opening): every assertion holds; the statement-only program lays the same rows; then
    /// the lies — a moved zerocheck round, a moved opened cell, a moved shift-bind round, a moved column-tie cell, a moved
    /// cross-tie cell, a moved WHIR leaf word — each fails an assertion, and the native door refuses each too.
    #[test]
    fn ledger_ssa_a_real_tree_ledger_proof_verifies_on_the_ssa_row() {
        use usdm_decider::poseidon2_compress::{lanes_of, DIGEST_LANES};
        use usdm_decider::whir_rec_block::AirBatchBusBundle;
        let (onr, dsr) = (vec![Fa4::from_u64(0xA1); 4], vec![Fa4::from_u64(0xB2); 4]);
        let dom = Fa4::from_u64(usdm_decider::whir_rec_block::SPEND_VALIDITY_DOMAIN);
        let s = lanes_of(&[0x5eed, 0x1ed6, 3, 4]);
        let sc = usdm_decider::slot_ledger::seed_commit_native(s);
        let pbs = spend_pbs();
        let filing = |a: &usdm_decider::poseidon2_compress::Digest, b: &usdm_decider::poseidon2_compress::Digest| {
            Some(usdm_decider::nullifier_insert_air::poseidon_pair_native(*a, *b))
        };
        let rows = usdm_decider::settlement_delta::plan_ledger_rows(s, pbs.len(), &[], &[], &filing).expect("the block is stateable");
        let t0 = std::time::Instant::now();
        let (proof, published, _) = usdm_decider::tree_ledger::prove_tree_ledger(&pbs, &rows, dom, &onr, &dsr, s, 0).expect("the tree ledger proves");
        println!("[v2-ledger] tree ledger proof {} B, proved in {} ms", proof.len(), t0.elapsed().as_millis());
        let native = |p: &[u8]| usdm_decider::tree_ledger::verify_tree_ledger(p, dom, &onr, &dsr, sc, &published, 0);
        assert!(native(&proof), "CALIBRATION: the node's door accepts the honest proof");
        let bind = usdm_decider::tree_ledger::tree_ledger_stated(dom, &onr, &dsr, sc, &published, 0).expect("the statement").bind;
        let plan = usdm_decider::tree_ledger::tree_ledger_plan(onr.len(), dsr.len()).expect("the plan");
        let build = |bytes: Option<&[u8]>| -> Result<Builder, String> {
            let mut b = Builder::new();
            let ba = b.public_vals(&bind);
            let mut sp: Vec<Ext> = (0..DIGEST_LANES).map(|c| b.konst_ext(Ea4::from(Fa4::from_u64(sc[c])))).collect();
            sp.push(b.konst_ext(usdm_decider::whir_rec_block::clock_const(0)));
            let cp = vec![b.konst_ext(Ea4::ZERO)];
            emit_tree_ledger_door(&mut b, &plan, &ba, &sp, &cp, bytes, &mut crate::verify_whir_ssa::WhirOnSsa)?;
            Ok(b)
        };
        let t1 = std::time::Instant::now();
        let b = build(Some(&proof)).expect("the program builds");
        if let Some(m) = &b.mismatch {
            panic!("⛔ an assertion of the SSA ledger door fails on an honest proof: {m}");
        }
        let vb = build(None).expect("the statement-only program builds");
        let (_, prog) = crate::ssa::lay(&b).expect("lays");
        let (_, vprog) = crate::ssa::lay(&vb).expect("lays");
        assert_eq!(prog.fixed, vprog.fixed, "⛔ the program depends on the proof's values");
        println!(
            "[v2-ledger] THE TREE LEDGER DOOR on the SSA row: {} ops, {} rows (T = 2^{}), built in {} ms",
            b.ops.len(),
            prog.rows,
            prog.nvars,
            t1.elapsed().as_millis()
        );
        assert!(prog.nvars <= 24, "⛔ the ledger door is past the SSA row's 2^24 cap: T = 2^{}", prog.nvars);
        // the lies: each one the native door refuses, and each one fails an assertion of the program
        let lie = |name: &str, f: &dyn Fn(&mut AirBatchBusBundle)| {
            let mut bb: AirBatchBusBundle = postcard::from_bytes(&proof).expect("decodes");
            f(&mut bb);
            let by = postcard::to_allocvec(&bb).expect("encodes");
            assert!(!native(&by), "CALIBRATION ({name}): the native door refuses the lie");
            assert!(build(Some(&by)).map_or(true, |b| b.mismatch.is_some()), "⛔ LIE passed the SSA door: {name}");
        };
        lie("a moved zerocheck round value", &|bb| bb.zcs[0].round_evals[2][1] += Ea4::ONE);
        lie("a moved opened step cell", &|bb| bb.zcs[0].opened[5] += Ea4::ONE);
        lie("a moved opened chain cell", &|bb| bb.zcs[1].opened[40] += Ea4::ONE);
        lie("a moved next-row value", &|bb| bb.zcs[1].shifted_opened[3] += Ea4::ONE);
        lie("a moved shift-bind round", &|bb| bb.shift_binds[0].round_evals[1][2] += Ea4::ONE);
        lie("a moved column-tie cell", &|bb| bb.column_tie_openings[0].0[0] += Ea4::ONE);
        lie("a moved cross-tie cell", &|bb| bb.cross_tie_openings[0].0[0] += Ea4::ONE);
        lie("a moved WHIR leaf word", &|bb| {
            if let Some(p3_whir::pcs::proof::QueryOpening::Base { values, .. }) = bb.round1.open.rounds.get_mut(0).and_then(|r| r.queries.get_mut(0)) {
                values[0] += Fa4::ONE;
            }
        });
    }

    /// ⭐ V2 (b) MEASUREMENT + GATE: THE TREE LEDGER'S ROUND FITS THE SSA ROW. The block's tree ledger statement (its two
    /// constant tables, read from `tree_ledger_plan`) laid as the light round its verifier opens: every claim the native
    /// batch verifier adds (each table's whole row at its zerocheck point, the chain's next-row set at the shift bind's
    /// point, every cross tie's committed end, both ends of every column tie), then the WHIR opening. Not yet in it: the two
    /// gates evaluated at the opened rows and the zerocheck rounds (piece 3). Asserts the program fits the 2^24 row cap.
    #[test]
    fn ledger_ssa_tree_ledger_round_fits_the_row_cap() {
        let plan = usdm_decider::tree_ledger::tree_ledger_plan(8, 8).expect("the statement's plan");
        let (shapes, sets, cross, cols) = (plan.shapes, plan.sets, plan.cross, plan.cols);
        let t0 = std::time::Instant::now();
        let mut b = Builder::new();
        let mut ch = crate::ssa::Chal::new();
        let mut lr = LightRoundSsa::begin(&mut b, &mut ch, &shapes, None).expect("the round begins");
        let mut opened = 0usize;
        let mut claim = |b: &mut Builder, ch: &mut crate::ssa::Chal, lr: &mut LightRoundSsa, t: usize, cs: &[usize]| {
            let pt: Vec<Ext> = (0..shapes[t].0).map(|_| ch.sample_ext(b)).collect();
            let v: Vec<Ext> = cs.iter().map(|_| b.load_ext(Ea4::ZERO)).collect();
            lr.add_claim_at(b, ch, t, cs, &v, &pt).expect("a claim");
            opened += cs.len();
        };
        for (t, &(_, w)) in shapes.iter().enumerate() {
            let all: Vec<usize> = (0..w).collect();
            claim(&mut b, &mut ch, &mut lr, t, &all);
            if !sets[t].is_empty() {
                claim(&mut b, &mut ch, &mut lr, t, &sets[t]);
            }
        }
        for ((t1, c1, _), (t2, c2, _)) in &cross {
            for (t, c) in [(*t1, c1), (*t2, c2)] {
                if t != usdm_decider::whir_rec_block::PUBLIC_BIND_TABLE {
                    claim(&mut b, &mut ch, &mut lr, t, c);
                }
            }
        }
        for (e1, e2) in &cols {
            for e in [e1, e2] {
                claim(&mut b, &mut ch, &mut lr, e.0, &e.1);
            }
        }
        lr.finish(&mut b, &mut ch, &mut crate::verify_whir_ssa::WhirOnSsa).expect("the program lays");
        let (_, prog) = crate::ssa::lay(&b).expect("lays");
        println!(
            "[v2-ledger] TREE LEDGER round on the SSA row: shapes {shapes:?}, next-row sets {:?}, {} cross + {} column ties, {opened} opened columns: {} ops, {} rows (T = 2^{}), built in {} ms",
            sets.iter().map(Vec::len).collect::<Vec<_>>(),
            cross.len(),
            cols.len(),
            b.ops.len(),
            prog.rows,
            prog.nvars,
            t0.elapsed().as_millis()
        );
        assert!(prog.nvars <= 24, "⛔ the tree ledger's round alone is past the SSA row's 2^24 cap: T = 2^{}", prog.nvars);
    }

    /// THE PIN: on a three-table stacked round (two arities, several columns, a padded table), the in-circuit weight equals
    /// the native constraint's weight at EVERY point of the hypercube, and moving one claim to another column disagrees.
    #[test]
    fn ledger_ssa_stacked_weight_is_the_native_constraint() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(42);
        let nvars = [3usize, 2, 3];
        let widths = [3usize, 2, 1];
        let arity = |nv: usize| nv.max(2);
        let shapes: Vec<TableShape> = nvars.iter().zip(widths).map(|(&nv, w)| TableShape::new(arity(nv), w)).collect();
        let claims_native: Vec<(usize, Vec<usize>, Vec<Ea4>)> = vec![
            (0, vec![0, 1, 2], (0..3).map(|_| rand_ea(&mut rng)).collect()),
            (1, vec![1], (0..2).map(|_| rand_ea(&mut rng)).collect()),
            (2, vec![0], (0..3).map(|_| rand_ea(&mut rng)).collect()),
            (0, vec![2], (0..3).map(|_| rand_ea(&mut rng)).collect()),
        ];
        let alpha = rand_ea(&mut rng);
        let oods: Vec<Ea4> = (0..2).map(|_| rand_ea(&mut rng)).collect();
        let native = |moved: bool| {
            let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
            let mut ch = challenger();
            for (i, (t, cols, pt)) in claims_native.iter().enumerate() {
                let mut lifted = vec![Ea4::ZERO; arity(nvars[*t]) - nvars[*t]];
                lifted.extend(pt.iter().copied());
                let cols: Vec<usize> = if moved && i == 1 { vec![0] } else { cols.clone() };
                let evals: Vec<Ea4> = cols.iter().map(|_| rand_ea(&mut rand::rngs::SmallRng::seed_from_u64(i as u64))).collect();
                lv.add_claim_at(*t, &cols, &evals, &Point::new(lifted), &mut ch);
            }
            for &y in &oods {
                // add_virtual_eval draws its own y from the challenger; the pin feeds the drawn y to the circuit
                let _ = y;
            }
            (lv, ch)
        };
        let (lv, mut ch) = native(false);
        // the virtual claims: the y each add_virtual_eval draws, mirrored by sampling the same challenger state
        let mut lv = lv;
        let mut drawn = Vec::new();
        for _ in 0..oods.len() {
            let mut probe = ch.clone();
            let y: Ea4 = probe.sample_algebra_element();
            drawn.push(y);
            lv.add_virtual_eval(rand_ea(&mut rng), &mut ch);
        }
        let k = lv.num_variables();
        let (poly, _) = lv.constraint(alpha).combine_new();
        let evals = poly.as_slice();
        let (lv_moved, _) = native(true);
        let mut moved_disagrees = false;
        for i in 0..(1usize << k) {
            let xp: Point<Ea4> = Point::hypercube(i, k);
            for (which, layout) in [(false, &lv), (true, &lv_moved)] {
                let mut b = Builder::new();
                let x: Vec<Ext> = xp.iter().map(|&v| b.load_ext(v)).collect();
                let a = b.load_ext(alpha);
                let claims: Vec<StackedClaim> = claims_native
                    .iter()
                    .enumerate()
                    .map(|(j, (t, cols, pt))| StackedClaim {
                        table: *t,
                        cols: if which && j == 1 { vec![0] } else { cols.clone() },
                        point: pt.iter().map(|&v| b.load_ext(v)).collect(),
                    })
                    .collect();
                let ys: Vec<Ext> = if which { Vec::new() } else { drawn.iter().map(|&v| b.load_ext(v)).collect() };
                let w = emit_stacked_weight(&mut b, layout, &nvars, &arity, &claims, &ys, a, &x).expect("emits");
                let got = b.ext_val(w);
                if !which {
                    assert_eq!(got, evals[i], "the in-circuit weight differs from the native constraint at hypercube point {i}");
                } else if got != evals[i] {
                    moved_disagrees = true;
                }
            }
        }
        assert!(moved_disagrees, "moving one claim to another column changed nothing: the weight does not read the selectors");
        let _ = <Ea4 as BasedVectorSpace<Fa4>>::DIMENSION;
    }
}

// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE TREE ON THE SSA ROW (docs/LEVEL-AGGREGATE-SPEC-20261115.md §12–13): a LEAF proves one payment's three carriers,
//! a MERGE proves up to `FAN_IN` children, a peer holds the payments' statements and one root.
//!
//! STATEMENTS. A leaf states an eight-lane digest `io`; a merge states `io` and the digest of the claims it carries.
//! * a leaf's `io` is the sponge (`PaddingFreeSponge`, the committed door's hash) of its three doors' public binds and
//!   gate public values, in door order — LOADED values the program hashes, so every leaf of a class shape runs the SAME
//!   program; the root rebuilds `io` from the payment's statement (`leaf_io`);
//! * a merge's `io` is the sponge of its children's `io`s, so the root rebuilds every `io` from the statements alone.
//!
//! PROGRAM CLAIMS FOLD UPWARD (`fold_claims`): a merge verifies each child in circuit, which leaves claims about the
//! child's PROGRAM (its preprocessed columns at two points); the merge folds every claim about one kind — its children's
//! own and the ones they carry about the kinds below them — into ONE, and states the digest of what it carries beside its
//! `io`. Only the root's carried claims reach a peer: `verify_root` checks O(kinds) = O(depth) program MLEs a block,
//! whatever its payments, then the root proof under its statement.
//!
//! §9.6 (the root's door, `verify_root`): (1) PoW — the block's; (2) the root by `ssa_door::verify`, every node below it
//! in circuit (`ssa_inner`), the root's folded program claims natively; (3) value — none created: a statement is exactly what the
//! three carrier doors check; (4) replay — the nullifier set, unchanged; (5) work — one SSA verify, one program MLE a
//! KIND in the tree (O(depth)), the statements' digests; (6) parity — each carrier
//! door is the native door's transcript and checks (pins d2 and the leaf pin), each child the SSA door's (m1);
//! (7) scale — a constant root per block, statements per payment; (8) (a) a proof every node checks.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use usdm_decider::air_zerocheck::AirConstraint;
use usdm_decider::committed_air::{Blinded, CarrierParams};
use usdm_decider::gate_trace::{GateInputs, GateProgram};
use usdm_decider::hiding_decider::{Ea4, Fa4};
use usdm_decider::member_path_gate::MemberTuple;
use usdm_decider::poseidon2_compress::Digest;

use crate::door_ssa::{emit_carrier_door, CarrierDoor, DoorKind};
use crate::ssa::{lay, Addr, Builder, Ext, Program, RATE, ZERO};
use crate::ssa_inner::{emit_ssa_child, ssa_gate_program, ChildShape};
use crate::verify_whir_ssa::WhirOnSsa;

/// Children a merge verifies.
pub const FAN_IN: usize = 2;
/// The largest root bundle a block may carry: a bound, set from the pinned root size when it is measured.
pub const ROOT_MAX_BYTES: usize = 4 << 20;

/// What a peer holds of one aggregated payment: exactly the arguments of its three carrier doors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentStatement {
    pub c0: Digest,
    pub c1: Digest,
    pub nf: Digest,
    pub lc: Digest,
    pub d: Digest,
    pub t1: Digest,
    pub fee: u64,
    pub hours: u64,
    /// The member tuple: leaf commit, binder, anchor, outputs.
    pub member: [Digest; 4],
    pub tags: Vec<Digest>,
}

/// A node's PROGRAM, named by its shape: a leaf's by its class shape, a merge's by its children's. Every node of one kind
/// runs one program (statement values are loaded, never constants), so claims about it from many proofs fold into one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// (the spend gate's option shape bits, the cover arm's tags)
    Leaf(usize, usize),
    Merge(Vec<Kind>),
    /// V2: the block's LEDGER node — its tree ledger proof verified in circuit (`ledger_ssa::emit_tree_ledger_door`);
    /// (the output-notes root's lanes, the deletion-set root's lanes), the statement's shape.
    Ledger(usize, usize),
}

/// A claim about one program's preprocessed columns: every one of them at `y` is `v` (limbs as canonical u32).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgClaim {
    pub kind: Kind,
    pub y: Vec<[u32; 4]>,
    pub v: Vec<[u32; 4]>,
}

/// A tree node's proof: the SSA proof, its kind, its statement digest, the program claims it carries about every kind
/// below it (folded: one a kind, in [`carried`] order) and the payments it covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeProof {
    pub proof: Vec<u8>,
    pub nvars: usize,
    pub kind: Kind,
    pub io: [u32; RATE],
    pub claims: Vec<ProgClaim>,
    pub payments: usize,
}

/// The kinds a node of `k` carries claims about: every kind strictly below it, sorted.
#[must_use]
pub fn carried(k: &Kind) -> Vec<Kind> {
    let mut set = std::collections::BTreeSet::new();
    if let Kind::Merge(ch) = k {
        for c in ch {
            set.insert(c.clone());
            for d in carried(c) {
                set.insert(d);
            }
        }
    }
    set.into_iter().collect()
}

fn u4(e: Ea4) -> [u32; 4] {
    let s: &[Fa4] = BasedVectorSpace::<Fa4>::as_basis_coefficients_slice(&e);
    [0, 1, 2, 3].map(|i| s[i].as_canonical_u32())
}
fn e4(v: &[u32; 4]) -> Ea4 {
    crate::door_ssa::ea(v.map(Fa4::from_u32))
}

/// One carrier door of a leaf: its door, its gate (permutation blocks inline), the bind and the gate's public lanes.
struct Part {
    door: CarrierDoor,
    gp: std::sync::Arc<GateProgram>,
    lay: GateInputs,
    bind: Vec<Fa4>,
    publics: Vec<Fa4>,
    /// The gate's option shape (the spend: bond, fee, claim tag, vault clock present, one bit each; 0 otherwise).
    shape_key: usize,
}

/// A carrier gate traced once per (class, shape): the trace depends on the shape alone, never on the statement's values
/// (its public values are program INPUTS), so the root check traces each class once, not once a payment.
fn traced(key: (u8, usize, usize, usize), f: impl FnOnce() -> Option<(GateProgram, GateInputs)>) -> Option<(std::sync::Arc<GateProgram>, GateInputs)> {
    type Cache = std::collections::HashMap<(u8, usize, usize, usize), (std::sync::Arc<GateProgram>, GateInputs)>;
    static C: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    let c = C.get_or_init(Default::default);
    if let Some(v) = c.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&key) {
        return Some(v.clone());
    }
    let (g, l) = f()?;
    let v = (std::sync::Arc::new(g), l);
    c.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key, v.clone());
    Some(v)
}

fn base_lanes(v: &[Ea4]) -> Result<Vec<Fa4>, String> {
    v.iter()
        .map(|e| {
            let s: &[Fa4] = BasedVectorSpace::<Fa4>::as_basis_coefficients_slice(e);
            if s[1..].iter().any(|x| *x != Fa4::ZERO) {
                Err("a gate public value is not a base-field element".to_string())
            } else {
                Ok(s[0])
            }
        })
        .collect()
}

fn parts(st: &PaymentStatement) -> Result<Vec<Part>, String> {
    let params = CarrierParams::LIVE;
    let mut out = Vec::with_capacity(3);
    // the note spend (blinded committed)
    let sp = usdm_decider::gate_trace::note_spend_statement(st.c0, st.c1, st.nf, st.lc, st.d, st.t1, st.fee, st.hours).ok_or("the note spend's door refuses this statement")?;
    let n = sp.laid_shape.0 + 1;
    let w = sp.laid_shape.1;
    let g = &sp.gate;
    let shape_key = usize::from(g.bond_amount.is_some()) | usize::from(g.fee_amount.is_some()) << 1 | usize::from(g.tag1.is_some()) << 2 | usize::from(g.vault.is_some()) << 3;
    let (gp, lay) = traced((0, w, n, shape_key), || usdm_decider::gate_trace::spend_validity_program(&sp.gate, w, n)).ok_or("the spend gate does not trace")?;
    let round_len = Blinded { inner: sp.gate.clone() }.degree(n) + 2;
    out.push(Part { door: CarrierDoor { kind: DoorKind::Committed, blinded: true, shape: (n, w), params, round_len, next_cols: Vec::new() }, gp, lay, bind: sp.bind.clone(), publics: base_lanes(&sp.publics)?, shape_key });
    // the member leg (blinded chained)
    let t = MemberTuple { leaf_commit: st.member[0], binder: st.member[1], anchor: st.member[2], outs: st.member[3] };
    let mb = usdm_decider::gate_trace::member_statement(&t);
    let n = mb.laid_shape.0 + 1;
    let w = mb.laid_shape.1;
    let (gp, lay) = traced((1, w, n, 0), || usdm_decider::gate_trace::member_path_program(w, n)).ok_or("the member gate does not trace")?;
    let round_len = Blinded { inner: mb.gate.clone() }.degree(n) + 2;
    let next_cols = lay.shifted.clone();
    out.push(Part { door: CarrierDoor { kind: DoorKind::Chained, blinded: true, shape: (n, w), params, round_len, next_cols }, gp, lay, bind: mb.bind.clone(), publics: base_lanes(&mb.publics)?, shape_key: 0 });
    // the cover arm (blinded chained)
    let cv = usdm_decider::gate_trace::cover_statement(&st.tags).ok_or("the cover door refuses this tag set")?;
    let n = cv.laid_shape.0 + 1;
    let w = cv.laid_shape.1;
    let (gp, lay) = traced((2, w, n, 0), || usdm_decider::gate_trace::cover_or_spend_program(w, n)).ok_or("the cover gate does not trace")?;
    let round_len = Blinded { inner: cv.gate.clone() }.degree(n) + 2;
    let next_cols = lay.shifted.clone();
    out.push(Part { door: CarrierDoor { kind: DoorKind::Chained, blinded: true, shape: (n, w), params, round_len, next_cols }, gp, lay, bind: cv.bind.clone(), publics: base_lanes(&cv.publics)?, shape_key: 0 });
    Ok(out)
}

/// The committed door's sponge over base words (`PaddingFreeSponge<Perm16, 16, 8, 8>`), natively.
fn sponge_words(words: &[Fa4]) -> [Fa4; RATE] {
    use p3_symmetric::CryptographicHasher;
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(crate::ssa::SEED);
    let h = usdm_decider::hiding_decider::SpongeHash::new(usdm_decider::hiding_decider::Perm16::new_from_rng_128(&mut rng));
    h.hash_iter(words.iter().copied())
}

/// The same sponge as SSA operations over addresses; returns the digest's lanes.
fn sponge_addrs(b: &mut Builder, words: &[Addr]) -> [Addr; RATE] {
    let mut st = [ZERO; 16];
    for chunk in words.chunks(RATE) {
        let mut inp = st;
        inp[..chunk.len()].copy_from_slice(chunk);
        st = b.perm(inp);
    }
    st[..RATE].try_into().expect("eight lanes")
}

fn leaf_words(ps: &[Part]) -> Vec<Fa4> {
    ps.iter().flat_map(|p| p.bind.iter().chain(&p.publics).copied()).collect()
}

/// A leaf's statement digest, natively from the payment's statement.
pub fn leaf_io(st: &PaymentStatement) -> Result<[Fa4; RATE], String> {
    Ok(sponge_words(&leaf_words(&parts(st)?)))
}

/// A leaf's program (`carriers = None`: the statement-only build every verifier makes).
fn leaf_builder(ps: &[Part], carriers: Option<[&[u8]; 3]>) -> Result<Builder, String> {
    let mut b = Builder::new();
    let words = leaf_words(ps);
    let io_v = if carriers.is_some() { sponge_words(&words) } else { [Fa4::ZERO; RATE] };
    let io = b.public_vals(&io_v);
    let vals = if carriers.is_some() { words.clone() } else { vec![Fa4::ZERO; words.len()] };
    let wa = b.load(&vals);
    let d = sponge_addrs(&mut b, &wa);
    for l in 0..RATE {
        b.assert_eq(Ext([d[l], ZERO, ZERO, ZERO]), Ext([io[l], ZERO, ZERO, ZERO]));
    }
    let mut k = 0usize;
    for (i, p) in ps.iter().enumerate() {
        let bind = &wa[k..k + p.bind.len()];
        k += p.bind.len();
        let pubs: Vec<Ext> = wa[k..k + p.publics.len()].iter().map(|&a| Ext([a, ZERO, ZERO, ZERO])).collect();
        k += p.publics.len();
        emit_carrier_door(&mut b, &p.door, bind, &p.gp, &p.lay, &pubs, carriers.map(|c| c[i]), &mut WhirOnSsa)?;
    }
    Ok(b)
}

/// Prove one payment's leaf from its three carriers (spend, member, cover).
#[must_use]
pub fn prove_leaf(st: &PaymentStatement, spend: &[u8], member: &[u8], cover: &[u8]) -> Option<Vec<u8>> {
    let ps = parts(st).ok()?;
    let b = leaf_builder(&ps, Some([spend, member, cover])).ok()?;
    if b.mismatch.is_some() {
        return None; // a carrier the door refuses has no leaf
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    let io = sponge_words(&leaf_words(&ps));
    let kind = leaf_kind(st, &ps);
    if cached(&kind).is_none() {
        let vb = leaf_builder(&ps, None).ok()?;
        remember(&kind, lay(&vb).ok()?.1);
    }
    postcard::to_allocvec(&NodeProof { proof, nvars: prog.nvars, kind, io: io.map(|x| x.as_canonical_u32()), claims: Vec::new(), payments: 1 }).ok()
}

fn leaf_kind(st: &PaymentStatement, ps: &[Part]) -> Kind {
    Kind::Leaf(ps[0].shape_key, st.tags.len())
}

/// The statement-only program of every kind met so far, built once (a leaf's from any statement of its kind).
fn program_cache() -> &'static std::sync::Mutex<std::collections::HashMap<Kind, std::sync::Arc<Program>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<Kind, std::sync::Arc<Program>>>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn cached(k: &Kind) -> Option<std::sync::Arc<Program>> {
    program_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(k).cloned()
}

fn remember(k: &Kind, p: Program) -> std::sync::Arc<Program> {
    let a = std::sync::Arc::new(p);
    program_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(k.clone(), a.clone());
    a
}

/// The statement-only program of a leaf of `st`'s kind.
fn leaf_program(st: &PaymentStatement) -> Result<(Kind, std::sync::Arc<Program>), String> {
    let ps = parts(st)?;
    let k = leaf_kind(st, &ps);
    if let Some(p) = cached(&k) {
        return Ok((k, p));
    }
    let b = leaf_builder(&ps, None)?;
    let (_, prog) = lay(&b)?;
    Ok((k.clone(), remember(&k, prog)))
}

/// A claim's base lanes, as the statement digest absorbs them (y then v, limb 0 first).
fn claim_lanes(c: &ProgClaim) -> Vec<Fa4> {
    c.y.iter().chain(&c.v).flat_map(|l| l.iter().map(|&x| Fa4::from_u32(x))).collect()
}

fn claims_digest(cs: &[ProgClaim]) -> [Fa4; RATE] {
    sponge_words(&cs.iter().flat_map(claim_lanes).collect::<Vec<_>>())
}

/// A child as its merge sees it: its kind and program, its statement (io, and for a merge its claims' digest), the
/// claims it carries, its proof.
struct Kid<'a> {
    kind: Kind,
    prog: std::sync::Arc<Program>,
    io: [Fa4; RATE],
    claims: Vec<ProgClaim>,
    proof: Option<&'a [u8]>,
}

/// A merge's program over children of the given kinds; with values (`proofs` present), also the claims it carries.
fn merge_builder(kids: &[Kid<'_>], with_values: bool) -> Result<(Builder, Vec<ProgClaim>), String> {
    let gate = ssa_gate_program().ok_or("the universal gate does not trace")?;
    let mut b = Builder::new();
    let z = |v: Fa4| if with_values { v } else { Fa4::ZERO };
    // per kind below: the claims to fold (built in circuit)
    let mut groups: std::collections::BTreeMap<Kind, Vec<crate::fold_claims::Claim>> = std::collections::BTreeMap::new();
    let mut ios: Vec<Addr> = Vec::new();
    for k in kids {
        let ioa = b.load(&k.io.map(z));
        ios.extend_from_slice(&ioa);
        let mut stmt = ioa.clone();
        if let Kind::Merge(_) = k.kind {
            // the child's carried claims: loaded, hashed to its statement's second half, then folded here
            let lanes: Vec<Fa4> = k.claims.iter().flat_map(claim_lanes).map(z).collect();
            let la = b.load(&lanes);
            let cd = sponge_addrs(&mut b, &la);
            stmt.extend_from_slice(&cd);
            let mut off = 0usize;
            for (ck, c) in carried(&k.kind).iter().zip(&k.claims) {
                if &c.kind != ck {
                    return Err("a child's claims are not its kind's".into());
                }
                let n = c.y.len();
                let ext = |i: usize| Ext([la[off + 4 * i], la[off + 4 * i + 1], la[off + 4 * i + 2], la[off + 4 * i + 3]]);
                let point: Vec<Ext> = (0..n).map(ext).collect();
                let vals: Vec<Ext> = (n..n + crate::ssa::NFIXED).map(ext).collect();
                off += 4 * (n + crate::ssa::NFIXED);
                groups.entry(ck.clone()).or_default().push(crate::fold_claims::Claim { point, cols: crate::fold_claims::Cols::All, vals });
            }
            if carried(&k.kind).len() != k.claims.len() {
                return Err("a child carries another number of claims than its kind".into());
            }
        }
        let shape = ChildShape::of(&k.prog, &stmt).ok_or("a child's statement is not its program's")?;
        let d = emit_ssa_child(&mut b, &shape, &gate, k.proof, &mut WhirOnSsa)?;
        let g = groups.entry(k.kind.clone()).or_default();
        g.push(crate::fold_claims::Claim { point: d.x.clone(), cols: crate::fold_claims::Cols::Bus, vals: d.fx.clone() });
        g.push(crate::fold_claims::Claim { point: d.r.clone(), cols: crate::fold_claims::Cols::All, vals: d.fr.clone() });
    }
    // fold each kind's claims into one
    let mut out = Vec::new();
    let mut out_lanes: Vec<Addr> = Vec::new();
    for (kind, claims) in &groups {
        let prog = cached(kind).ok_or("a child kind's program is not built")?;
        let f = crate::fold_claims::emit_fold(&mut b, claims, prog.nvars, with_values.then_some(&prog.fixed[..]))?;
        let ev = |e: &Ext| u4(b.ext_val(*e));
        out.push(ProgClaim { kind: kind.clone(), y: f.y.iter().map(ev).collect(), v: f.v.iter().map(ev).collect() });
        for e in f.y.iter().chain(&f.v) {
            out_lanes.extend_from_slice(&e.0);
        }
    }
    // the statement: io = sponge(children's io), then the digest of the carried claims
    let io_d = sponge_addrs(&mut b, &ios);
    let cd_d = sponge_addrs(&mut b, &out_lanes);
    let vals: Vec<Fa4> = io_d.iter().chain(&cd_d).map(|&a| if with_values { b.val(a) } else { Fa4::ZERO }).collect();
    let st = b.public_vals(&vals);
    for l in 0..2 * RATE {
        let d = if l < RATE { io_d[l] } else { cd_d[l - RATE] };
        b.assert_eq(Ext([d, ZERO, ZERO, ZERO]), Ext([st[l], ZERO, ZERO, ZERO]));
    }
    Ok((b, out))
}

/// The statement-only program of a merge of children of these kinds.
fn merge_program(kinds: &[Kind], st_of: &dyn Fn(&Kind) -> Option<std::sync::Arc<Program>>) -> Result<std::sync::Arc<Program>, String> {
    let k = Kind::Merge(kinds.to_vec());
    if let Some(p) = cached(&k) {
        return Ok(p);
    }
    let kids: Vec<Kid<'_>> = kinds
        .iter()
        .map(|c| {
            let prog = st_of(c).ok_or("a child kind's program is not built")?;
            let claims = carried(c).into_iter().map(|kk| {
                let n = cached(&kk).map_or(0, |p| p.nvars);
                ProgClaim { kind: kk, y: vec![[0; 4]; n], v: vec![[0; 4]; crate::ssa::NFIXED] }
            }).collect();
            Ok(Kid { kind: c.clone(), prog, io: [Fa4::ZERO; RATE], claims, proof: None })
        })
        .collect::<Result<_, String>>()?;
    let (b, _) = merge_builder(&kids, false)?;
    let (_, prog) = lay(&b)?;
    Ok(remember(&k, prog))
}

/// The program with its statement values set (a verifier's build has zeros there).
fn stated(prog: &Program, vals: &[Fa4]) -> Program {
    let mut p = prog.clone();
    for (i, a) in prog.statement.iter().enumerate() {
        for q in &mut p.public {
            if q.0 == *a {
                q.1 = vals[i];
            }
        }
    }
    p
}

/// The canonical tree over `n` payments: leaves in carried order, merged `FAN_IN` at a time, level by level.
#[derive(Clone, Debug)]
pub enum Tree {
    Leaf(usize),
    Merge(Vec<Tree>),
    /// the block's ledger node (V2)
    Ledger,
}

/// ⭐ V2 (spec LEVEL-AGGREGATE §15.5) — what a peer holds of a block's LEDGER statement: exactly the arguments the tree
/// ledger door's statement is built from (`tree_ledger::tree_ledger_stated(..).bind`, the seed commitment, the block
/// clock) and the roots' lane counts that fix its shape.
/// cons: none on state — nothing is written to disk; the ledger node's program is cached in RAM once per ledger SHAPE
/// (`Kind::Ledger(onr_len, dsr_len)`: one shape in production), f(fixed constants), never f(blocks or history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerStatement {
    pub bind: Vec<Fa4>,
    pub seed_commit: Digest,
    pub clock_h: u64,
    pub onr_len: usize,
    pub dsr_len: usize,
}

/// The ledger node's statement words, in the order its program loads them: the bind, the seed commitment's lanes, the
/// clock.
fn ledger_words(ls: &LedgerStatement) -> Vec<Fa4> {
    let mut w = ls.bind.clone();
    w.extend(ls.seed_commit.iter().map(|&x| Fa4::from_u64(x)));
    w.push(Fa4::from_u64(ls.clock_h));
    w
}

/// The ledger node's statement digest, natively from the ledger statement.
#[must_use]
pub fn ledger_io(ls: &LedgerStatement) -> [Fa4; RATE] {
    sponge_words(&ledger_words(ls))
}

/// The ledger node's program (`proof = None`: the statement-only build every verifier makes). The statement words are
/// LOADED and hashed to the public `io`, so every block of one ledger shape runs the same program.
fn ledger_builder(ls: &LedgerStatement, proof: Option<&[u8]>) -> Result<Builder, String> {
    let plan = usdm_decider::tree_ledger::tree_ledger_plan(ls.onr_len, ls.dsr_len).ok_or("the ledger statement has no plan")?;
    let mut b = Builder::new();
    let words = ledger_words(ls);
    let io_v = if proof.is_some() { sponge_words(&words) } else { [Fa4::ZERO; RATE] };
    let io = b.public_vals(&io_v);
    let vals = if proof.is_some() { words.clone() } else { vec![Fa4::ZERO; words.len()] };
    let wa = b.load(&vals);
    let d = sponge_addrs(&mut b, &wa);
    for l in 0..RATE {
        b.assert_eq(Ext([d[l], ZERO, ZERO, ZERO]), Ext([io[l], ZERO, ZERO, ZERO]));
    }
    let nb = ls.bind.len();
    let lift = |a: Addr| Ext([a, ZERO, ZERO, ZERO]);
    let step_publics: Vec<Ext> = wa[nb..nb + usdm_decider::poseidon2_compress::DIGEST_LANES + 1].iter().map(|&a| lift(a)).collect();
    let chain_publics = vec![Ext::ZERO]; // the expected challenge fold: the protocol's constant zero
    crate::ledger_ssa::emit_tree_ledger_door(&mut b, &plan, &wa[..nb], &step_publics, &chain_publics, proof, &mut WhirOnSsa)?;
    Ok(b)
}

fn ledger_kind(ls: &LedgerStatement) -> Kind {
    Kind::Ledger(ls.onr_len, ls.dsr_len)
}

fn ledger_program(ls: &LedgerStatement) -> Result<(Kind, std::sync::Arc<Program>), String> {
    let k = ledger_kind(ls);
    if let Some(p) = cached(&k) {
        return Ok((k, p));
    }
    let b = ledger_builder(ls, None)?;
    let (_, prog) = lay(&b)?;
    Ok((k.clone(), remember(&k, prog)))
}

/// Prove the block's ledger node from its tree ledger proof (`tree_ledger::prove_tree_ledger`'s bytes). `None` when the
/// proof is not one the ledger door accepts (it has no satisfying trace).
#[must_use]
pub fn prove_ledger_node(ls: &LedgerStatement, ledger_proof: &[u8]) -> Option<Vec<u8>> {
    let b = ledger_builder(ls, Some(ledger_proof)).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    ledger_program(ls).ok()?;
    let io = ledger_io(ls);
    postcard::to_allocvec(&NodeProof { proof, nvars: prog.nvars, kind: ledger_kind(ls), io: io.map(|x| x.as_canonical_u32()), claims: Vec::new(), payments: 0 }).ok()
}

/// The block's tree: the payments' canonical tree and the ledger node, merged once (a block of no payments: the ledger
/// node under one merge, so a block's root is always a merge).
#[must_use]
pub fn block_tree(n: usize) -> Tree {
    match tree_of(n) {
        Some(t) => Tree::Merge(vec![t, Tree::Ledger]),
        None => Tree::Merge(vec![Tree::Ledger]),
    }
}

#[must_use]
pub fn tree_of(n: usize) -> Option<Tree> {
    if n == 0 {
        return None;
    }
    let mut level: Vec<Tree> = (0..n).map(Tree::Leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut it = level.into_iter().peekable();
        while it.peek().is_some() {
            next.push(Tree::Merge(it.by_ref().take(FAN_IN).collect()));
        }
        level = next;
    }
    level.pop()
}

/// A subtree's kind and statement digest, natively from the statements (building every program it meets).
fn kind_io(t: &Tree, st: &[PaymentStatement]) -> Option<(Kind, [Fa4; RATE])> {
    kind_io_with(t, st, None)
}

/// [`kind_io`] over a tree that may hold the block's ledger node (`ls`, its statement).
fn kind_io_with(t: &Tree, st: &[PaymentStatement], ls: Option<&LedgerStatement>) -> Option<(Kind, [Fa4; RATE])> {
    match t {
        Tree::Leaf(i) => {
            let s = st.get(*i)?;
            let (k, _) = leaf_program(s).ok()?;
            Some((k, leaf_io(s).ok()?))
        }
        Tree::Ledger => {
            let l = ls?;
            let (k, _) = ledger_program(l).ok()?;
            Some((k, ledger_io(l)))
        }
        Tree::Merge(cs) => {
            let kids: Vec<(Kind, [Fa4; RATE])> = cs.iter().map(|c| kind_io_with(c, st, ls)).collect::<Option<_>>()?;
            let kinds: Vec<Kind> = kids.iter().map(|k| k.0.clone()).collect();
            merge_program(&kinds, &|k| cached(k)).ok()?;
            let ios: Vec<Fa4> = kids.iter().flat_map(|k| k.1).collect();
            Some((Kind::Merge(kinds), sponge_words(&ios)))
        }
    }
}

/// Prove a merge of the subtrees `cs` (global leaf indices into `st`) from their node proofs.
fn prove_merge_in(st: &[PaymentStatement], cs: &[&Tree], proofs: &[Vec<u8>]) -> Option<Vec<u8>> {
    prove_merge_in_with(st, None, cs, proofs)
}

fn prove_merge_in_with(st: &[PaymentStatement], ls: Option<&LedgerStatement>, cs: &[&Tree], proofs: &[Vec<u8>]) -> Option<Vec<u8>> {
    if cs.is_empty() || cs.len() > FAN_IN || cs.len() != proofs.len() {
        return None;
    }
    let nodes: Vec<NodeProof> = proofs.iter().map(|b| postcard::from_bytes(b).ok()).collect::<Option<_>>()?;
    let mut kids = Vec::new();
    for (t, n) in cs.iter().zip(&nodes) {
        let (k, io) = kind_io_with(t, st, ls)?;
        if k != n.kind || io.map(|x| x.as_canonical_u32()) != n.io {
            return None;
        }
        kids.push(Kid { kind: k.clone(), prog: cached(&k)?, io, claims: n.claims.clone(), proof: Some(&n.proof[..]) });
    }
    let kinds: Vec<Kind> = kids.iter().map(|k| k.kind.clone()).collect();
    merge_program(&kinds, &|k| cached(k)).ok()?;
    let (b, claims) = merge_builder(&kids, true).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay(&b).ok()?;
    if std::env::var_os("MONEROUSD_PROVE_PROGRESS").is_some() {
        let (p, c, a, bi, h, l) = crate::ssa::census(&b);
        eprintln!("[ssa-census] merge of {}: {p} permutations, {c} Merkle levels, {a} multiply-adds, {bi} Bits, {h} halvings, {l} loaded lanes; {} rows (T = 2^{})", kids.len(), prog.rows, prog.nvars);
    }
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    let io = sponge_words(&kids.iter().flat_map(|k| k.io).collect::<Vec<_>>());
    postcard::to_allocvec(&NodeProof { proof, nvars: prog.nvars, kind: Kind::Merge(kinds), io: io.map(|x| x.as_canonical_u32()), claims, payments: nodes.iter().map(|n| n.payments).sum() }).ok()
}

/// Prove a merge of children, each a CANONICAL subtree (`tree_of` of its own payments) given by the statements it covers
/// in carried order and its node proof.
#[must_use]
pub fn prove_merge(children: &[(Vec<PaymentStatement>, Vec<u8>)]) -> Option<Vec<u8>> {
    fn shifted(t: &Tree, by: usize) -> Tree {
        match t {
            Tree::Leaf(i) => Tree::Leaf(i + by),
            Tree::Merge(cs) => Tree::Merge(cs.iter().map(|c| shifted(c, by)).collect()),
            Tree::Ledger => Tree::Ledger,
        }
    }
    let st: Vec<PaymentStatement> = children.iter().flat_map(|c| c.0.clone()).collect();
    let mut trees = Vec::new();
    let mut off = 0usize;
    for (sts, _) in children {
        trees.push(shifted(&tree_of(sts.len())?, off));
        off += sts.len();
    }
    let refs: Vec<&Tree> = trees.iter().collect();
    let proofs: Vec<Vec<u8>> = children.iter().map(|c| c.1.clone()).collect();
    prove_merge_in(&st, &refs, &proofs)
}

/// Prove a block's root from its leaves (one a payment, in carried order), merging along the canonical tree.
#[must_use]
pub fn prove_root(statements: &[PaymentStatement], leaves: &[Vec<u8>]) -> Option<Vec<u8>> {
    fn go(t: &Tree, st: &[PaymentStatement], leaves: &[Vec<u8>]) -> Option<Vec<u8>> {
        match t {
            Tree::Leaf(i) => leaves.get(*i).cloned(),
            Tree::Merge(cs) => {
                let proofs: Vec<Vec<u8>> = cs.iter().map(|c| go(c, st, leaves)).collect::<Option<_>>()?;
                let refs: Vec<&Tree> = cs.iter().collect();
                prove_merge_in(st, &refs, &proofs)
            }
            Tree::Ledger => None, // a payments-only tree holds no ledger node ([`prove_block_root`] does)
        }
    }
    if statements.len() != leaves.len() {
        return None;
    }
    go(&tree_of(statements.len())?, statements, leaves)
}

/// ⭐ V2 — prove a BLOCK's ONE root: its payments' leaves merged along the canonical tree, and its ledger node
/// ([`prove_ledger_node`]), merged once ([`block_tree`]). The block then carries this root alone: every payment's carriers
/// and the block's ledger proof are verified inside it.
#[must_use]
pub fn prove_block_root(statements: &[PaymentStatement], leaves: &[Vec<u8>], ls: &LedgerStatement, ledger_node: &[u8]) -> Option<Vec<u8>> {
    fn go(t: &Tree, st: &[PaymentStatement], ls: &LedgerStatement, leaves: &[Vec<u8>], ledger: &[u8]) -> Option<Vec<u8>> {
        match t {
            Tree::Leaf(i) => leaves.get(*i).cloned(),
            Tree::Ledger => Some(ledger.to_vec()),
            Tree::Merge(cs) => {
                let proofs: Vec<Vec<u8>> = cs.iter().map(|c| go(c, st, ls, leaves, ledger)).collect::<Option<_>>()?;
                let refs: Vec<&Tree> = cs.iter().collect();
                prove_merge_in_with(st, Some(ls), &refs, &proofs)
            }
        }
    }
    if statements.len() != leaves.len() {
        return None;
    }
    go(&block_tree(statements.len()), statements, ls, leaves, ledger_node)
}

/// ⭐ V2 — verify a block's ONE root natively ([`verify_root`]'s checks over [`block_tree`]): every statement digest from
/// the payments' statements and the ledger statement bottom up, the root's carried claims against each kind's program, the
/// root proof by the SSA door under its statement.
#[must_use]
pub fn verify_block_root(statements: &[PaymentStatement], ls: &LedgerStatement, root: &[u8]) -> bool {
    verify_tree(&block_tree(statements.len()), statements, Some(ls), root)
}

/// Verify a block's root natively: the statement digests from the payments' statements bottom up, the root's carried
/// claims against the program of each kind (O(kinds) = O(depth) MLEs a block, whatever its payments), and the root
/// proof by the SSA door under its statement.
#[must_use]
pub fn verify_root(statements: &[PaymentStatement], root: &[u8]) -> bool {
    if statements.is_empty() {
        return false;
    }
    let Some(tree) = tree_of(statements.len()) else { return false };
    verify_tree(&tree, statements, None, root)
}

fn verify_tree(tree: &Tree, statements: &[PaymentStatement], ls: Option<&LedgerStatement>, root: &[u8]) -> bool {
    if root.len() > ROOT_MAX_BYTES {
        return false;
    }
    let Ok(np) = postcard::from_bytes::<NodeProof>(root) else { return false };
    if np.payments != statements.len() {
        return false;
    }
    let Some((kind, io)) = kind_io_with(tree, statements, ls) else { return false };
    if kind != np.kind || io.map(|x| x.as_canonical_u32()) != np.io {
        return false;
    }
    let Some(prog) = cached(&kind) else { return false };
    let want = carried(&kind);
    if np.claims.len() != want.len() {
        return false;
    }
    for (c, k) in np.claims.iter().zip(&want) {
        let Some(p) = cached(k) else { return false };
        if &c.kind != k || c.y.len() != p.nvars || c.v.len() != crate::ssa::NFIXED {
            return false;
        }
        let y: Vec<Ea4> = c.y.iter().map(e4).collect();
        let v: Vec<Ea4> = c.v.iter().map(e4).collect();
        if p.fixed_at(&y) != v {
            return false; // a folded claim the program does not satisfy
        }
    }
    let mut svals: Vec<Fa4> = io.to_vec();
    if let Kind::Merge(_) = kind {
        svals.extend_from_slice(&claims_digest(&np.claims));
    }
    if svals.len() != prog.statement.len() || np.nvars != prog.nvars {
        return false;
    }
    crate::ssa_door::verify(&np.proof, &stated(&prog, &svals))
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdm_decider::member_path_gate::{prove_member_path_carrier, MEMBER_PATH_DEPTH};
    use usdm_decider::whir_rec_block::{NoteOwner, SpendValidityWitness, PROTOCOL_FEE_ATOMIC};

    fn dig(seed: u64) -> Digest {
        core::array::from_fn(|i| (seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919 + 1)) % 2_130_706_433)
    }

    /// One payment's three REAL carriers (made by the wallet's own provers) and its statement.
    pub(crate) fn payment(seed: u64) -> (PaymentStatement, [Vec<u8>; 3]) {
        let w = SpendValidityWitness {
            value_in: PROTOCOL_FEE_ATOMIC,
            owner: NoteOwner { ask: dig(seed + 1), nk: dig(seed + 2), seed: dig(seed + 3) },
            value_out: 0,
            fee: PROTOCOL_FEE_ATOMIC,
            lc_blind: dig(seed + 4),
            out0_value: 0,
            out0_opening: dig(seed + 5),
            out1_value: 0,
            out1_opening: dig(seed + 6),
        };
        let d = dig(seed + 7);
        let (spend, cms, nf, lc, t1) = usdm_decider::whir_rec_block::prove_spend_validity_carrier_claiming_bytes(&w, d, w.lc_blind, 0).expect("the wallet proves its spend");
        assert!(usdm_decider::whir_rec_block::verify_note_spend_bytes(&spend, cms[0], cms[1], nf, lc, d, t1, w.fee, 0), "CALIBRATION: the native spend door accepts it");
        let sibs: Vec<Digest> = (0..MEMBER_PATH_DEPTH as u64).map(|k| dig(seed + 100 + k)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|k| (k as u64 + seed) % 3 == 1).collect();
        let (member, t) = prove_member_path_carrier(dig(seed + 8), &sibs, &dirs, dig(seed + 9), dig(seed + 10), dig(seed + 11)).expect("the wallet proves its membership");
        let bound = dig(seed + 12);
        let tags: Vec<Digest> = (0..8u64).map(|j| usdm_decider::nf_sparse_air::cover_tag_native(bound, j)).collect();
        let wit = vec![usdm_decider::nf_sparse_air::TagWitness::Decoy; 8];
        let cover = usdm_decider::nf_sparse_air::prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("the wallet proves its cover");
        assert!(usdm_decider::nf_sparse_air::verify_spend_or_decoy_bytes(&cover, &tags), "CALIBRATION: the native cover door accepts it");
        let st = PaymentStatement { c0: cms[0], c1: cms[1], nf, lc, d, t1, fee: w.fee, hours: 0, member: [t.leaf_commit, t.binder, t.anchor, t.outs], tags };
        (st, [spend, member, cover])
    }

    /// ⭐⭐ A LEAF: one payment's three real carriers verified wholly on the SSA row and proven; the root check (a tree of
    /// one) accepts it against the payment's statement and refuses it against another; a carrier the door refuses
    /// has no leaf.
    #[test]
    fn t1_a_leaf_proves_a_payment_and_the_root_checks_it() {
        let (st, c) = payment(1);
        let ps = parts(&st).expect("parts");
        let t0 = std::time::Instant::now();
        let b = leaf_builder(&ps, Some([&c[0], &c[1], &c[2]])).expect("builds");
        assert_eq!(b.mismatch, None, "⛔ an assertion of the leaf fails on honest carriers");
        let (_, prog) = lay(&b).expect("lays");
        let alu = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Alu(_))).count();
        let perms = b.ops.iter().filter(|o| matches!(o, crate::ssa::Op::Perm { .. } | crate::ssa::Op::Comp { .. })).count();
        println!("[agg-t1] leaf: {} ops ({alu} multiply-adds, {perms} permutations), {} rows (T = 2^{}), built in {} ms", b.ops.len(), prog.rows, prog.nvars, t0.elapsed().as_millis());
        let t1 = std::time::Instant::now();
        let leaf = prove_leaf(&st, &c[0], &c[1], &c[2]).expect("⛔ the leaf does not prove");
        let pms = t1.elapsed().as_millis();
        let t2 = std::time::Instant::now();
        assert!(verify_root(&[st.clone()], &leaf), "⛔ the root check refuses an honest leaf");
        println!("[agg-t1] leaf proof {} B, prove {pms} ms, root check {} ms", leaf.len(), t2.elapsed().as_millis());
        let mut other = st.clone();
        other.fee += 1;
        assert!(!verify_root(&[other], &leaf), "⛔ LIE: the leaf passed for another statement");
        let mut bad = c[2].clone();
        let k = bad.len() / 2;
        bad[k] ^= 1;
        assert!(prove_leaf(&st, &c[0], &c[1], &bad).is_none(), "⛔ LIE: a corrupted cover carrier made a leaf");
    }

    /// ⭐⭐⭐ A MERGE: two leaves merged; the root check accepts it against the two statements in order and refuses the
    /// swapped order, a moved carried claim, and a missing payment.
    #[test]
    fn t2_a_merge_of_two_leaves_is_checked_at_the_root() {
        let (s1, c1) = payment(1);
        let (s2, c2) = payment(2);
        let l1 = prove_leaf(&s1, &c1[0], &c1[1], &c1[2]).expect("leaf 1");
        let l2 = prove_leaf(&s2, &c2[0], &c2[1], &c2[2]).expect("leaf 2");
        let t0 = std::time::Instant::now();
        let root = prove_root(&[s1.clone(), s2.clone()], &[l1, l2]).expect("⛔ the merge does not prove");
        let pms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_root(&[s1.clone(), s2.clone()], &root), "⛔ the root check refuses an honest merge");
        let np: NodeProof = postcard::from_bytes(&root).expect("decodes");
        println!("[agg-t2] merge of two leaves: T = 2^{}, root {} B ({} carried claims), prove {pms} ms, root check {} ms", np.nvars, root.len(), np.claims.len(), t1.elapsed().as_millis());
        assert!(!verify_root(&[s2.clone(), s1.clone()], &root), "⛔ LIE: the swapped statements passed");
        let mut np2 = np.clone();
        np2.claims[0].v[3][0] ^= 1;
        assert!(!verify_root(&[s1.clone(), s2.clone()], &postcard::to_allocvec(&np2).expect("encodes")), "⛔ LIE: a moved carried claim passed");
        assert!(!verify_root(&[s1], &root), "⛔ LIE: the root passed for one of its two payments");
    }

    /// ⭐⭐ V2 — A BLOCK'S ONE ROOT: one real payment's leaf and the block's LEDGER NODE (a real tree ledger proof verified in
    /// circuit) merged into one root, checked natively by `verify_block_root` from the payment's statement and the ledger
    /// statement. The ledger node proves (its program is the ledger door); a ledger proof the door refuses makes no node;
    /// and the root refuses a moved bind lane, another clock, another seed commitment, a payment statement that is not the
    /// leaf's, and the payments-only check (`verify_root`) of the same bytes.
    #[test]
    fn t5_a_block_root_carries_its_ledger_node() {
        let (proof, bind, sc, onr_len, dsr_len) = crate::ledger_ssa::tests::ledger_fixture();
        let ls = LedgerStatement { bind, seed_commit: sc, clock_h: 0, onr_len, dsr_len };
        let t0 = std::time::Instant::now();
        let node = prove_ledger_node(&ls, &proof).expect("⛔ the ledger node does not prove");
        let np: NodeProof = postcard::from_bytes(&node).expect("decodes");
        println!("[v2-block] ledger node: T = 2^{}, {} B, prove {} ms", np.nvars, node.len(), t0.elapsed().as_millis());
        let mut bad = proof.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(prove_ledger_node(&ls, &bad).is_none(), "⛔ LIE: a corrupted ledger proof made a ledger node");
        let (st, c) = payment(1);
        let leaf = prove_leaf(&st, &c[0], &c[1], &c[2]).expect("the leaf proves");
        let t1 = std::time::Instant::now();
        let root = prove_block_root(&[st.clone()], &[leaf], &ls, &node).expect("⛔ the block root does not prove");
        let pms = t1.elapsed().as_millis();
        let t2 = std::time::Instant::now();
        assert!(verify_block_root(&[st.clone()], &ls, &root), "⛔ the block root check refuses an honest block");
        let rp: NodeProof = postcard::from_bytes(&root).expect("decodes");
        println!("[v2-block] block root over 1 payment + its ledger: T = 2^{}, root {} B ({} carried claims), prove {pms} ms, check {} ms", rp.nvars, root.len(), rp.claims.len(), t2.elapsed().as_millis());
        let mut moved = ls.clone();
        moved.bind[3] += Fa4::ONE;
        assert!(!verify_block_root(&[st.clone()], &moved, &root), "⛔ LIE: a moved ledger bind lane passed");
        assert!(!verify_block_root(&[st.clone()], &LedgerStatement { clock_h: 1, ..ls.clone() }, &root), "⛔ LIE: another block clock passed");
        let mut sc2 = ls.seed_commit;
        sc2[0] ^= 1;
        assert!(!verify_block_root(&[st.clone()], &LedgerStatement { seed_commit: sc2, ..ls.clone() }, &root), "⛔ LIE: another seed commitment passed");
        let (other, _) = payment(2);
        assert!(!verify_block_root(&[other], &ls, &root), "⛔ LIE: another payment's statement passed");
        assert!(!verify_root(&[st], &root), "⛔ LIE: the block root passed the payments-only check");
    }

    /// ⭐ THE TREE AT DEPTH TWO: three payments make the canonical tree Merge(Merge(L0, L1), Merge(L2)) — a merge whose
    /// children are merges, carrying the claims they fold. The root proves, every level fits a table, the root checks
    /// O(kinds) claims, and its lies are refused: a dropped payment, a swapped pair, a moved carried claim.
    #[test]
    fn t3_a_root_over_three_payments_merges_merges() {
        let ps: Vec<(PaymentStatement, [Vec<u8>; 3])> = (11..14).map(payment).collect();
        let st: Vec<PaymentStatement> = ps.iter().map(|p| p.0.clone()).collect();
        let leaves: Vec<Vec<u8>> = ps.iter().map(|(s, c)| prove_leaf(s, &c[0], &c[1], &c[2]).expect("a leaf")).collect();
        let t0 = std::time::Instant::now();
        let root = prove_root(&st, &leaves).expect("⛔ the depth-two root does not prove");
        let pms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_root(&st, &root), "⛔ the root check refuses an honest depth-two root");
        let np: NodeProof = postcard::from_bytes(&root).expect("decodes");
        println!("[agg-t3] root over three payments: T = 2^{}, root {} B ({} carried claims), merges prove {pms} ms, root check {} ms", np.nvars, root.len(), np.claims.len(), t1.elapsed().as_millis());
        assert!(!verify_root(&st[..2], &root), "⛔ LIE: the root passed for two of its three payments");
        assert!(!verify_root(&[st[1].clone(), st[0].clone(), st[2].clone()], &root), "⛔ LIE: a swapped pair passed");
        let mut np2 = np.clone();
        let last = np2.claims.len() - 1;
        np2.claims[last].v[0][0] ^= 1;
        assert!(!verify_root(&st, &postcard::to_allocvec(&np2).expect("encodes")), "⛔ LIE: a moved carried claim passed");
    }

    /// ⭐ THE BUNDLE MERGE (spec §14.7 piece T3, lane speed5's ask): two bundles of two, each its own canonical root, made
    /// apart, merged by `prove_merge` into a bundle of four — the perfect tree `tree_of(4)` — which `verify_root` takes
    /// unchanged. Lies refused: the bundles' statements in the other order, a member dropped, a member's statement
    /// moved, one bundle's proof standing for the other's.
    #[test]
    fn t4_two_bundles_of_two_merge_into_a_bundle_of_four() {
        let ps: Vec<(PaymentStatement, [Vec<u8>; 3])> = (21..25).map(payment).collect();
        let st: Vec<PaymentStatement> = ps.iter().map(|p| p.0.clone()).collect();
        let leaf = |i: usize| prove_leaf(&ps[i].0, &ps[i].1[0], &ps[i].1[1], &ps[i].1[2]).expect("a leaf");
        let a = prove_root(&st[0..2], &[leaf(0), leaf(1)]).expect("bundle a");
        let b = prove_root(&st[2..4], &[leaf(2), leaf(3)]).expect("bundle b");
        assert!(verify_root(&st[0..2], &a) && verify_root(&st[2..4], &b), "⛔ a bundle of two does not check");
        let t0 = std::time::Instant::now();
        let four = prove_merge(&[(st[0..2].to_vec(), a.clone()), (st[2..4].to_vec(), b.clone())]).expect("⛔ two bundles do not merge");
        let pms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_root(&st, &four), "⛔ the root check refuses an honest bundle of four");
        let np: NodeProof = postcard::from_bytes(&four).expect("decodes");
        println!("[agg-t4] bundle of four from two of two: T = 2^{}, root {} B ({} carried claims), merge {pms} ms, root check {} ms", np.nvars, four.len(), np.claims.len(), t1.elapsed().as_millis());
        let swapped: Vec<PaymentStatement> = st[2..4].iter().chain(&st[0..2]).cloned().collect();
        assert!(!verify_root(&swapped, &four), "⛔ LIE: the bundles' statements in the other order passed");
        assert!(!verify_root(&st[..3], &four), "⛔ LIE: a member dropped passed");
        let mut moved = st.clone();
        moved[3].fee += 1;
        assert!(!verify_root(&moved, &four), "⛔ LIE: a member's moved statement passed");
        assert!(prove_merge(&[(st[0..2].to_vec(), b), (st[2..4].to_vec(), a)]).is_none(), "⛔ LIE: one bundle's proof stood for the other's");
    }
}

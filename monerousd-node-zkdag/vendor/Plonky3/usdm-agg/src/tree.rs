// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! STEP 5 — THE TREE (spec §12): a LEAF proves one payment's three carriers; a MERGE proves up to `FAN_IN` children;
//! a peer holds the payments' statements and one root.
//!
//! WHAT EACH NODE STATES. A node's public value is its statement digest `io` (the verifier row's statement sponge):
//! * a leaf's `io` absorbs its three carriers' public binds in the order their doors absorb them (each chunk on an
//!   `Io` row tied to the inner transcript's duplexing of the same lanes, `verify_prog::emit_door`), so the leaf's `io`
//!   IS the payment's statement and nothing else;
//! * a merge's `io` absorbs, per child: the child's bind `vm_bind(child io)` (tied the same way), each coordinate of the
//!   child's zerocheck point `r` (as it is drawn), and the child's DEFERRED PROGRAM CLAIM `(β, Σ_f β^f·flag_f(r))`.
//!
//! THE DEFERRED PROGRAM CLAIM. A merge verifies its child wholly in circuit except one thing a circuit cannot afford: that
//! the child's committed flag cells are its program's (`vm::program_claim_holds` is an MLE over the whole program). So
//! the merge commits the child's opened flags folded at β (drawn after pass 1 hashed them, `GateEval::compile_with_combo`)
//! into its own statement; [`verify_root`] checks every such claim natively against the program it rebuilds from the
//! statements, and the root's own program claim through [`vm::verify_vm`].
//!
//! §9.6 (the root's door, `verify_root`; spec §3 D1 for the block): (1) PoW — the block's, unchanged; (2) the root proof
//! by `vm::verify_vm` (the chained door + its program claim), every node below it in circuit, every deferred claim
//! natively; (3) value — none created here: a statement is what the three carrier doors would have checked, and the
//! ledger applies it exactly as it applies a full payment; (4) replay — the nullifier set, unchanged; (5) work — one
//! chained-door verify, one MLE of a program per node (O(T · flags)), the statements' digests; (6) parity — every check
//! the three carrier doors make is made in circuit by the same gate (gate_trace pins) and the same transcript
//! (verify_prog pins); (7) scale — a constant root per block, statements per payment, nodes ≤ 2·payments; (8) (a) a
//! proof every node checks; a LYING PROVER (a child false in one place) is refused at the door that reads the lie.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};
use usdm_decider::gate_trace::{
    cover_or_spend_program, cover_statement, member_path_program, member_statement, note_spend_statement, spend_validity_program,
    with_opaque_perms,
};
use usdm_decider::hiding_decider::{Ea4, Fa4};
use usdm_decider::member_path_gate::MemberTuple;
use usdm_decider::poseidon2_compress::Digest;

use crate::gate_eval::{with_publics, Builder, GateEval};
use crate::isa::*;
use crate::verify_prog::{emit_door, Door, DoorKind};
use crate::vm::{program_flags_at, prove_vm, verify_vm, vm_bind, VmGate};

/// Children a merge verifies.
pub const FAN_IN: usize = 3;
/// The largest root bundle a block may carry. NOT MEASURED yet: set from the pinned root size the day it is measured;
/// a bound here, never a guess at the honest size.
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
    pub member: MemberTuple,
    pub tags: Vec<Digest>,
}

/// One merge's claim about one child (module doc).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deferred {
    pub r: Vec<[u32; 4]>,
    pub beta: [u32; 4],
    pub combo: [u32; 4],
}

/// A tree node's proof: the verifier-row proof, its shape, its statement digest, and the deferred claims of its whole
/// subtree in canonical order (depth-first, children in carried order, each merge's own claims after its children's).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeProof {
    pub proof: Vec<u8>,
    pub nvars: usize,
    pub io: [u32; RATE],
    pub deferred: Vec<Deferred>,
    /// How many payments the subtree covers (a leaf: 1).
    pub payments: usize,
}

fn e4(v: &[u32; 4]) -> Ea4 {
    ea(&v.map(|x| Fa4::from_u32(x)))
}
fn u4(e: Ea4) -> [u32; 4] {
    let s = e.as_basis_coefficients_slice();
    [0, 1, 2, 3].map(|i| p3_field::PrimeField32::as_canonical_u32(&s[i]))
}
fn io_f(io: &[u32; RATE]) -> [Fa4; RATE] {
    io.map(Fa4::from_u32)
}

/// A carrier inner proof as the leaf verifies it.
struct Inner {
    door: Door,
    ev: GateEval,
}

fn class_inners(st: &PaymentStatement) -> Result<[Inner; 3], String> {
    let params = usdm_decider::committed_air::CarrierParams::LIVE;
    let sp = note_spend_statement(st.c0, st.c1, st.nf, st.lc, st.d, st.t1, st.fee, st.hours).ok_or("the note spend's door refuses this statement")?;
    let (w, laid) = (sp.laid_shape.1, sp.laid_shape.0);
    let (gp, lay) = with_opaque_perms(|| spend_validity_program(&sp.gate, w, laid + 1)).ok_or("the spend gate does not trace")?;
    let spend = Inner {
        ev: GateEval::compile(&with_publics(&gp, lay.publics_at(), &sp.publics), &lay, true).map_err(String::from)?,
        door: Door { kind: DoorKind::BlindedCommitted, shape: sp.laid_shape, bind: sp.bind, params },
    };
    let mb = member_statement(&st.member);
    let (gp, lay) = with_opaque_perms(|| member_path_program(mb.laid_shape.1, mb.laid_shape.0 + 1)).ok_or("the member gate does not trace")?;
    let member = Inner {
        ev: GateEval::compile(&with_publics(&gp, lay.publics_at(), &mb.publics), &lay, true).map_err(String::from)?,
        door: Door { kind: DoorKind::BlindedChained, shape: mb.laid_shape, bind: mb.bind, params },
    };
    let cv = cover_statement(&st.tags).ok_or("the cover door refuses this tag set")?;
    let (gp, lay) = with_opaque_perms(|| cover_or_spend_program(cv.laid_shape.1, cv.laid_shape.0 + 1)).ok_or("the cover gate does not trace")?;
    let cover = Inner {
        ev: GateEval::compile(&with_publics(&gp, lay.publics_at(), &cv.publics), &lay, true).map_err(String::from)?,
        door: Door { kind: DoorKind::BlindedChained, shape: cv.laid_shape, bind: cv.bind, params },
    };
    Ok([spend, member, cover])
}

fn clr_row(b: &mut Builder) {
    b.push(Instr { clr: true, cclr: true, ..Default::default() }, [Fa4::ZERO; ND]);
}
fn stmt_row(b: &mut Builder) {
    b.push(Instr { stmt: true, ..Default::default() }, [Fa4::ZERO; ND]);
}

/// A leaf's program (verifier: `carriers = None`; prover: the three carriers' bytes, spend / member / cover).
fn leaf_program(st: &PaymentStatement, carriers: Option<[&[u8]; 3]>) -> Result<Builder, String> {
    let inners = class_inners(st)?;
    let mut b = Builder::default();
    clr_row(&mut b);
    for (k, inner) in inners.iter().enumerate() {
        emit_door(&mut b, &inner.door, &inner.ev, carriers.map(|c| c[k]), &mut |_, _, _, _| {})?;
    }
    stmt_row(&mut b);
    Ok(b)
}

/// The statement sponge's digest over chunks absorbed as `Io` rows (overwrite the chunk's lanes, permute).
fn io_sponge(chunks: &[Vec<Fa4>]) -> [Fa4; RATE] {
    use p3_symmetric::Permutation;
    let perm = usdm_decider::sponge_chain_air::perm_for_seed(SEED);
    let mut st = [Fa4::ZERO; WIDTH];
    for c in chunks {
        st[..c.len()].copy_from_slice(c);
        perm.permute_mut(&mut st);
    }
    core::array::from_fn(|i| st[i])
}

fn bind_chunks(bind: &[Fa4], out: &mut Vec<Vec<Fa4>>) {
    for c in bind.chunks(RATE) {
        out.push(c.to_vec());
    }
}

/// A leaf's statement digest, natively.
fn leaf_io(st: &PaymentStatement) -> Result<[Fa4; RATE], String> {
    let inners = class_inners(st)?;
    let mut chunks = Vec::new();
    for inner in &inners {
        bind_chunks(&inner.door.bind, &mut chunks);
    }
    Ok(io_sponge(&chunks))
}

/// What a merge needs of one child to verify it: its statement digest, its trace's variable count.
#[derive(Clone, Copy)]
struct ChildShape {
    io: [Fa4; RATE],
    nvars: usize,
}

fn vm_gate_eval(child: ChildShape) -> Result<GateEval, String> {
    let w = WIDTH_VM;
    let shifted: Vec<usize> = (SHIFT_LO..SHIFT_HI).collect();
    let lay = usdm_decider::gate_trace::GateInputs { width: w, shifted: shifted.clone(), nvars: child.nvars, publics: RATE };
    let ns = shifted.len();
    let gp = with_opaque_perms(|| {
        usdm_decider::gate_trace::trace(lay.total(), |ins| {
            let oob = usdm_decider::air_zerocheck::OobLatch::new();
            let row = usdm_decider::air_zerocheck::Row::new(&ins[..w], &oob);
            let next = ins[w..w + ns].to_vec();
            let at = |c: usize, _p: &[usdm_decider::gate_trace::Sym]| next[c - SHIFT_LO];
            let io: [usdm_decider::gate_trace::Sym; RATE] = core::array::from_fn(|i| ins[lay.publics_at() + i]);
            VmGate { gamma: usdm_decider::gate_trace::Sym::ZERO, io }.residuals(&row, &at, &[])
        })
    })
    .ok_or("the verifier row's gate does not trace")?;
    let publics: Vec<Ea4> = child.io.iter().map(|&x| Ea4::from(x)).collect();
    let flags: Vec<u32> = (FLAGS as u32..WIDTH_VM as u32).collect();
    GateEval::compile_with_combo(&with_publics(&gp, lay.publics_at(), &publics), &lay, false, &flags).map_err(String::from)
}

/// The `Io` row that puts a value of `X[reg]` (the prover's `v`) into the statement, the unit asserting it.
fn io_value_row(b: &mut Builder, reg: u8, v: Ea4) {
    let mut w = [Fa4::ZERO; ND];
    w[..4].copy_from_slice(v.as_basis_coefficients_slice());
    let mut i = Instr { kind: Some(Kind::Io), am: 0x0F, ..Default::default() };
    i.alu[0] = Some(Alu { a: SrcA::X(reg), b: SrcB::Kc, c: Some(SrcC::Dx(0)), wr: None, zero: true, kc: -Ea4::ONE });
    b.push(i, w);
}

/// A merge's program (verifier: `proofs = None`), and the deferred claims it makes (prover side: read off the run).
fn merge_program(children: &[ChildShape], proofs: Option<&[&[u8]]>, claims: Option<&[Deferred]>) -> Result<Builder, String> {
    let mut b = Builder::default();
    clr_row(&mut b);
    for (k, child) in children.iter().enumerate() {
        let ev = vm_gate_eval(*child)?;
        let door = Door { kind: DoorKind::Chained, shape: (child.nvars, WIDTH_VM), bind: vm_bind(&child.io), params: usdm_decider::committed_air::CarrierParams::LIVE };
        let claim = claims.map(|c| c[k].clone());
        let rv: Vec<Ea4> = claim.as_ref().map(|c| c.r.iter().map(e4).collect()).unwrap_or_default();
        emit_door(&mut b, &door, &ev, proofs.map(|p| p[k]), &mut |b, kk, reg, v| {
            io_value_row(b, reg, rv.get(kk).copied().unwrap_or(v));
        })?;
        // the child's deferred claim (β, combo) into the statement
        let (beta, combo) = claim.as_ref().map_or((Ea4::ZERO, Ea4::ZERO), |c| (e4(&c.beta), e4(&c.combo)));
        let mut w = [Fa4::ZERO; ND];
        w[..4].copy_from_slice(beta.as_basis_coefficients_slice());
        w[4..8].copy_from_slice(combo.as_basis_coefficients_slice());
        let mut i = Instr { kind: Some(Kind::Io), am: 0xFF, ..Default::default() };
        i.alu[0] = Some(Alu { a: SrcA::X(X_BETA as u8), b: SrcB::Kc, c: Some(SrcC::Dx(0)), wr: None, zero: true, kc: -Ea4::ONE });
        i.alu[1] = Some(Alu { a: SrcA::X(18), b: SrcB::Kc, c: Some(SrcC::Dx(1)), wr: None, zero: true, kc: -Ea4::ONE });
        b.push(i, w);
    }
    stmt_row(&mut b);
    Ok(b)
}

/// A merge's statement digest, natively, from its children and its claims about them.
fn merge_io(children: &[ChildShape], claims: &[Deferred]) -> [Fa4; RATE] {
    let mut chunks = Vec::new();
    for (c, d) in children.iter().zip(claims) {
        bind_chunks(&vm_bind(&c.io), &mut chunks);
        for r in &d.r {
            chunks.push(e4(r).as_basis_coefficients_slice().to_vec());
        }
        let mut bc = e4(&d.beta).as_basis_coefficients_slice().to_vec();
        bc.extend_from_slice(e4(&d.combo).as_basis_coefficients_slice());
        chunks.push(bc);
    }
    io_sponge(&chunks)
}

/// A child's deferred claim holds: its program's flags at `r`, folded at β, are the committed combination.
fn claim_holds(prog: &[Instr], nvars: usize, d: &Deferred) -> bool {
    let r: Vec<Ea4> = d.r.iter().map(e4).collect();
    let Some(flags) = program_flags_at(prog, nvars, &r) else { return false };
    let beta = e4(&d.beta);
    let (mut acc, mut p) = (Ea4::ZERO, Ea4::ONE);
    for v in flags {
        acc += p * v;
        p *= beta;
    }
    acc == e4(&d.combo)
}

/// The claims a merge makes about its children, natively from the children's proofs: each child's zerocheck point r,
/// the β the merge's pass 1 draws over that child's reads, and the child's opened flags folded at β.
fn claims_of(children: &[ChildShape], proofs: &[&[u8]]) -> Result<Vec<Deferred>, String> {
    let mut out = Vec::new();
    for (child, bytes) in children.iter().zip(proofs) {
        let (zc, next, shape) = usdm_decider::committed_air::zerocheck_of_chained_carrier(bytes).ok_or("a child proof does not parse")?;
        if shape != (child.nvars, WIDTH_VM) || zc.opened.len() != WIDTH_VM {
            return Err("a child proof's shape is not the one stated".into());
        }
        let ev = vm_gate_eval(*child)?;
        let inputs = ev.lay.assemble(&zc.opened, &next, &zc.r, &vec![Ea4::ZERO; RATE]).ok_or("a child proof's openings are not its gate's inputs")?;
        let (_rho, beta) = ev.challenges(&inputs);
        let (mut combo, mut p) = (Ea4::ZERO, Ea4::ONE);
        for v in &zc.opened[FLAGS..] {
            combo += p * *v;
            p *= beta;
        }
        out.push(Deferred { r: zc.r.iter().map(|e| u4(*e)).collect(), beta: u4(beta), combo: u4(combo) });
    }
    Ok(out)
}

/// Prove one payment's leaf from its three carriers.
#[must_use]
pub fn prove_leaf(st: &PaymentStatement, spend: &[u8], member: &[u8], cover: &[u8]) -> Option<Vec<u8>> {
    let b = leaf_program(st, Some([spend, member, cover])).ok()?;
    let (proof, io, shape) = prove_vm(&b.prog, &b.stream, 32).ok()?;
    if io != leaf_io(st).ok()? {
        return None; // the program stated something else than the statement: a bug, never a proof
    }
    let np = NodeProof { proof, nvars: shape.0, io: io.map(|x| p3_field::PrimeField32::as_canonical_u32(&x)), deferred: Vec::new(), payments: 1 };
    postcard::to_allocvec(&np).ok()
}

/// Prove a merge of children (each: the statements it covers in carried order, its node proof).
#[must_use]
pub fn prove_merge(children: &[(Vec<PaymentStatement>, Vec<u8>)]) -> Option<Vec<u8>> {
    if children.is_empty() || children.len() > FAN_IN {
        return None;
    }
    let nodes: Vec<NodeProof> = children.iter().map(|(_, b)| postcard::from_bytes(b).ok()).collect::<Option<_>>()?;
    let shapes: Vec<ChildShape> = nodes.iter().map(|n| ChildShape { io: io_f(&n.io), nvars: n.nvars }).collect();
    let proofs: Vec<&[u8]> = nodes.iter().map(|n| n.proof.as_slice()).collect();
    let claims = claims_of(&shapes, &proofs).ok()?;
    let b = merge_program(&shapes, Some(&proofs), Some(&claims)).ok()?;
    let (proof, io, shape) = prove_vm(&b.prog, &b.stream, 32).ok()?;
    if io != merge_io(&shapes, &claims) {
        return None;
    }
    let mut deferred = Vec::new();
    for n in &nodes {
        deferred.extend(n.deferred.iter().cloned());
    }
    deferred.extend(claims);
    let payments = nodes.iter().map(|n| n.payments).sum();
    let np = NodeProof { proof, nvars: shape.0, io: io.map(|x| p3_field::PrimeField32::as_canonical_u32(&x)), deferred, payments };
    postcard::to_allocvec(&np).ok()
}

/// The canonical tree over `n` payments: leaves in carried order, merged `FAN_IN` at a time, level by level. A node is a
/// range of payments; its children are the ranges of the level below.
#[derive(Clone, Debug)]
pub enum Tree {
    Leaf(usize),
    Merge(Vec<Tree>),
}

#[must_use]
pub fn canonical_tree(n: usize) -> Option<Tree> {
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

/// Prove a block's root from its leaves (one a payment, in carried order), merging along the canonical tree.
#[must_use]
pub fn prove_root(statements: &[PaymentStatement], leaves: &[Vec<u8>]) -> Option<Vec<u8>> {
    fn go(t: &Tree, st: &[PaymentStatement], leaves: &[Vec<u8>]) -> Option<(Vec<PaymentStatement>, Vec<u8>)> {
        match t {
            Tree::Leaf(i) => Some((vec![st.get(*i)?.clone()], leaves.get(*i)?.clone())),
            Tree::Merge(cs) => {
                let kids: Vec<(Vec<PaymentStatement>, Vec<u8>)> = cs.iter().map(|c| go(c, st, leaves)).collect::<Option<_>>()?;
                let covered = kids.iter().flat_map(|k| k.0.clone()).collect();
                Some((covered, prove_merge(&kids)?))
            }
        }
    }
    if statements.len() != leaves.len() {
        return None;
    }
    go(&canonical_tree(statements.len())?, statements, leaves).map(|r| r.1)
}

/// Verify a block's root natively: every leaf's statement digest from the statements, every merge's from its children
/// and the deferred claims, every deferred claim against the program rebuilt from the statements, and the root proof
/// itself (`vm::verify_vm`: the chained door and the root's own program claim). Claims are consumed in the order
/// `prove_merge` lists them: a merge's subtrees' claims depth-first, then its own.
#[must_use]
pub fn verify_root(statements: &[PaymentStatement], root: &[u8]) -> bool {
    fn node(t: &Tree, st: &[PaymentStatement], claims: &mut core::slice::Iter<'_, Deferred>) -> Option<(ChildShape, Builder)> {
        match t {
            Tree::Leaf(i) => {
                let s = st.get(*i)?;
                let io = leaf_io(s).ok()?;
                let prog = leaf_program(s, None).ok()?;
                let nvars = (prog.len() + 1).max(32).next_power_of_two().trailing_zeros() as usize;
                Some((ChildShape { io, nvars }, prog))
            }
            Tree::Merge(cs) => {
                let kids: Vec<(ChildShape, Builder)> = cs.iter().map(|c| node(c, st, claims)).collect::<Option<_>>()?;
                let mut own = Vec::new();
                for (shape, prog) in &kids {
                    let d = claims.next()?;
                    if d.r.len() != shape.nvars || !claim_holds(&prog.prog, shape.nvars, d) {
                        return None;
                    }
                    own.push(d.clone());
                }
                let shapes: Vec<ChildShape> = kids.iter().map(|k| k.0).collect();
                let io = merge_io(&shapes, &own);
                let prog = merge_program(&shapes, None, None).ok()?;
                let nvars = (prog.len() + 1).max(32).next_power_of_two().trailing_zeros() as usize;
                Some((ChildShape { io, nvars }, prog))
            }
        }
    }
    if statements.is_empty() || root.len() > ROOT_MAX_BYTES {
        return false;
    }
    let Ok(np) = postcard::from_bytes::<NodeProof>(root) else { return false };
    if np.payments != statements.len() {
        return false;
    }
    let Some(tree) = canonical_tree(statements.len()) else { return false };
    let mut claims = np.deferred.iter();
    let Some((shape, prog)) = node(&tree, statements, &mut claims) else { return false };
    claims.next().is_none()
        && io_f(&np.io) == shape.io
        && np.nvars == shape.nvars
        && verify_vm(&np.proof, &prog.prog, &shape.io, (np.nvars, WIDTH_VM))
}

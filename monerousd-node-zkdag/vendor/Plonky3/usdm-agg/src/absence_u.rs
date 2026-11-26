// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ THE UNIVERSAL CARRIER FAMILY (A-F114 phase 3, lane speed5, 2026-11-22; docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md).
//!
//! User 2026-11-22: *"we need a single universal merge program with child constants bound into the claims."* The
//! structural carrier (`absence_ssa`) names a merge's program by its children's, so a merge at depth d carries a claim about
//! every program below it and its proof grows a claim a level. Here a FAMILY of three programs (the record LEAF, the one
//! MERGE, the list RESHAPE) is laid at one shape, every one of them verifies a child of ANY of the three with one circuit,
//! and every claim of a tree is about ONE table, so a node carries exactly one claim at any depth (pin u1 MEASURED it).
//!
//! * **ONE TABLE.** The three programs' fixed columns, stacked in four slots (leaf, merge, reshape, zero), are one
//!   multilinear table with two top variables `(k1, k0)`. A child's deferred claim at `y` is a claim at `(k1, k0, y)`, and
//!   every claim folds into ONE; the root checks it natively against the stacked table. The kind bits are the prover's;
//!   `k1·k0 = 0` keeps them off the zero slot, and a child whose proof is not valid for the program they name fails the
//!   root's check, so a false kind admits nothing.
//! * **CHILD CONSTANTS, BOUND.** A child's public part (address, multiplicity and, for a constant, its value) is LOADED
//!   (`ssa_inner::emit_ssa_child_loaded`), hashed in circuit and asserted equal to `D0 + k0·(D1 − D0) + k1·(D2 − D0)`, the
//!   digest of the program the bits name. `D0, D1, D2` ride every statement down the tree and up to the root, which checks
//!   them against the programs it rebuilds. They are statement values, so no program contains its own hash.
//! * **A LEAF CARRIES ONE TRUE CLAIM** (its parent cannot tell it is a leaf): the table at the zero point.
//! * **RESHAPE** restates a child over a list of the same length in which any slot may be replaced, the replaced slots'
//!   bits forced to zero at both ends: it needs no proof beyond the child (dropping an entry only drops claims; an entry
//!   stated uncreated is only ever checked less, and the spend wrapper refuses an unset bit). A wallet's notes join, and its
//!   spent notes leave, its one fixed-length list this way.
//! * **THE SPEND WRAPPER** (outside the family) verifies one family child the same way and exposes only the nullifier, the
//!   binder, the leaf commitment and the chain end.
//!
//! COST, STATED (RAM, in process): one `Family` per list shape. Each program's fixed table is `NFIXED` (289) × 2^15 rows ×
//! 4 B = 37.9 MB, so ~152 MB for the three programs and the wrapper; the stacked table only a PROVER's fold reads is
//! 289 × 2^17 × 4 B = 151.5 MB, built on a prover's first fold (`Family::comb`) and never by a verifier. Every term is
//! f(fixed constants) (the list shape, NFIXED, 2^15 rows), the same at any height, and nothing is written to disk: each
//! `to_allocvec` here returns a proof's bytes to its caller.
//! §9.6: (2) the proof by the SSA door, every node below in circuit; (3) none created; (4) the node checks the end against
//! its window and the records after it; (5) one SSA verify plus three program MLEs; (7) a fixed proof size; (8) (a).

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::absence_ssa::{abs_io, base, bit, chain_step, lanes_of_u32, lanes_u32, nfs_digest, spend_io, Entry, Lanes, LeafVals, Record};
use crate::fold_claims::{emit_fold, Claim, Cols};
use crate::ssa::{lay_uniform, Addr, Builder, Ext, Program, NFIXED, RATE, ZERO};
use crate::ssa_inner::{emit_ssa_child_loaded, ssa_gate_program, LoadedPub};
use crate::tree_ssa::{e4, sponge_addrs, sponge_words, stated, u4};
use crate::verify_whir_ssa::WhirOnSsa;

/// The family's programs, by kind.
pub const LEAF: u8 = 0;
pub const MERGE: u8 = 1;
pub const RESHAPE: u8 = 2;
const KINDS: usize = 3;
/// Top variables of the stacked table (four slots: three programs and a zero slot).
const KBITS: usize = 2;

/// A family member's statement: `io ‖ D0 ‖ D1 ‖ D2 ‖ claim digest`.
pub const STMT_LANES: usize = (2 + KINDS) * RATE;

/// The one claim a node carries: the stacked table at `y` (`nvars + 2` coordinates) is `v` (every fixed column).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UClaim {
    pub y: Vec<[u32; 4]>,
    pub v: Vec<[u32; 4]>,
}

impl UClaim {
    /// The claim's base lanes (`y` then `v`, limb 0 first): what a parent loads and hashes to the claim digest.
    #[must_use]
    pub fn lanes(&self) -> Vec<Fa4> {
        self.y.iter().chain(&self.v).flat_map(|l| l.iter().map(|&x| Fa4::from_u32(x))).collect()
    }
    fn digest(&self) -> Lanes {
        sponge_words(&self.lanes())
    }
}

/// A family proof: the SSA proof, its kind, its abs statement, its one claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UProof {
    pub proof: Vec<u8>,
    pub kind: u8,
    pub shape: Shape,
    pub nfs_d: [u32; RATE],
    pub c_start: [u32; RATE],
    pub c_end: [u32; RATE],
    pub f_start: Vec<bool>,
    pub f_end: Vec<bool>,
    pub claim: UClaim,
}

/// One family: its three programs at one shape, their public digests, the leaf's true claim, the spend wrapper's program,
/// and (for provers) the stacked table.
pub struct Family {
    pub shape: Shape,
    pub nvars: usize,
    pub pub_len: usize,
    pub progs: Vec<Program>,
    pub digests: Vec<Lanes>,
    pub leaf_claim: UClaim,
    pub wrap: Program,
    comb: std::sync::OnceLock<Vec<Vec<Fa4>>>,
}

impl Family {
    /// The stacked fixed columns (leaf, merge, reshape, zero rows): `NFIXED` columns of `2^(nvars + 2)`, built once, on a
    /// prover's first fold.
    pub(crate) fn comb(&self) -> &[Vec<Fa4>] {
        self.comb.get_or_init(|| {
            let t = 1usize << self.nvars;
            (0..NFIXED).map(|c| self.progs.iter().flat_map(|pr| pr.fixed[c].iter().copied()).chain(core::iter::repeat_n(Fa4::ZERO, t)).collect()).collect()
        })
    }
    /// The stacked table at `y` (first coordinates `k1, k0`), natively from the three programs.
    fn comb_at(&self, y: &[Ea4]) -> Option<Vec<Ea4>> {
        if y.len() != self.nvars + KBITS {
            return None;
        }
        let (k1, k0, rest) = (y[0], y[1], &y[KBITS..]);
        let w = [(Ea4::ONE - k1) * (Ea4::ONE - k0), (Ea4::ONE - k1) * k0, k1 * (Ea4::ONE - k0)];
        let mut out = vec![Ea4::ZERO; NFIXED];
        for (i, p) in self.progs.iter().enumerate() {
            for (o, f) in out.iter_mut().zip(p.fixed_at(rest)) {
                *o += w[i] * f;
            }
        }
        Some(out)
    }
    fn digest_words(&self) -> Vec<Fa4> {
        self.digests.iter().flat_map(|d| d.iter().copied()).collect()
    }
}

/// ⭐ A-F114 (B′) — THE ONE SHAPE A SPEND'S WRAPPER IS ADMITTED AT, as the prover crate names it: one entry over 8 tag and 8
/// output chunks, 16 records a leaf. The node's `canon_chain::SPEND_SHAPE` is derived from its own constants and asserted
/// equal to this one, so the tree and the door can never admit two shapes.
pub const ADMITTED_SPEND_SHAPE: Shape = (1, 8, 8, 16);

/// ⭐ A-F114 (B′) — THE FAMILY'S STACKED TABLE AS ONE PROGRAM, for a parent that carries a wrapper's own deferred claim
/// (`USpend.claim`) instead of checking it natively. Its fixed columns are the family's `comb` (leaf, merge, reshape, then
/// zero rows, each `2^nvars`), at `nvars + KBITS`: a big-endian MLE over that stack weighs the three programs by
/// `(1−k1)(1−k0)`, `(1−k1)k0`, `k1(1−k0)`, exactly [`Family::comb_at`], so the tree's generic root check
/// (`Program::fixed_at`) decides the same claim `verify_spend` decides. No public part, no statement: it is never proven,
/// only evaluated.
#[must_use]
pub fn comb_program(fam: &Family) -> Program {
    Program { rows: 0, nvars: fam.nvars + KBITS, fixed: fam.comb().to_vec(), public: Vec::new(), statement: Vec::new(), quarter: false }
}

/// A program's public part as its parent binds it: per entry `(address, multiplicity, value)`, the value zero for a
/// statement entry (the first `STMT_LANES`, which are the parent's own lanes), in the program's canonical order.
#[must_use]
pub fn pub_digest(prog: &Program) -> Lanes {
    let words: Vec<Fa4> = prog
        .public
        .iter()
        .enumerate()
        .flat_map(|(j, &(a, v, m))| [Fa4::from_u32(a), Fa4::from_u64(m), if j < STMT_LANES { Fa4::ZERO } else { v }])
        .collect();
    sponge_words(&words)
}

fn claim_lanes_len(nvars: usize) -> usize {
    4 * (nvars + KBITS + NFIXED)
}

/// The shared parts every node of a tree holds: the three program digests, loaded once.
struct Shared {
    ds: Vec<[Addr; RATE]>,
}

/// ⭐ ONE FAMILY CHILD, VERIFIED IN CIRCUIT: its kind bits, its carried claim, its statement `io ‖ D0 ‖ D1 ‖ D2 ‖ claim
/// digest`, its public part loaded and bound to the digest its bits name, its proof by the loaded door; its three claims
/// (carried, and the two deferred, at `(k1, k0, ·)`) pushed onto `claims`.
#[allow(clippy::too_many_arguments)]
fn emit_family_child(
    b: &mut Builder,
    fam: Option<&Family>,
    nvars: usize,
    pub_len: usize,
    sh: &Shared,
    io: [Addr; RATE],
    kid: Option<&UProof>,
    claims: &mut Vec<Claim>,
) -> Result<(), String> {
    let gate = ssa_gate_program().ok_or("the universal gate does not trace")?;
    let kind = kid.map_or(0, |k| k.kind);
    if usize::from(kind) >= KINDS {
        return Err("a child of no family kind".into());
    }
    let k1 = b.load_ext(Ea4::from(bit(kind & 2 != 0)));
    let k0 = b.load_ext(Ea4::from(bit(kind & 1 != 0)));
    for x in [k1, k0] {
        let nx = b.sub(Ext::ZERO, x);
        b.assert_mul_add_zero(x, x, nx);
    }
    b.assert_mul_add_zero(k1, k0, Ext::ZERO); // never the zero slot
    let cl_v: Vec<Fa4> = kid.map_or(vec![Fa4::ZERO; claim_lanes_len(nvars)], |k| k.claim.lanes());
    if cl_v.len() != claim_lanes_len(nvars) {
        return Err("a child's claim is not the family's shape".into());
    }
    let cla = b.load(&cl_v);
    let cd = sponge_addrs(b, &cla);
    let ext = |j: usize| Ext([cla[4 * j], cla[4 * j + 1], cla[4 * j + 2], cla[4 * j + 3]]);
    let np = nvars + KBITS;
    claims.push(Claim { point: (0..np).map(ext).collect(), cols: Cols::All, vals: (np..np + NFIXED).map(ext).collect() });
    let mut stmt: Vec<Addr> = io.to_vec();
    for d in &sh.ds {
        stmt.extend_from_slice(d);
    }
    stmt.extend_from_slice(&cd);
    let cprog = fam.filter(|_| kid.is_some()).map(|f| &f.progs[usize::from(kind)]);
    let mut entries: Vec<LoadedPub> = Vec::with_capacity(pub_len);
    let mut words: Vec<Addr> = Vec::with_capacity(3 * pub_len);
    for j in 0..pub_len {
        let (a, v, m) = cprog.and_then(|p| p.public.get(j).copied()).unwrap_or((0, Fa4::ZERO, 0));
        let aa = b.load(&[Fa4::from_u32(a)])[0];
        let ma = b.load(&[Fa4::from_u64(m)])[0];
        let va = if j < STMT_LANES { stmt[j] } else { b.load(&[v])[0] };
        words.extend([aa, ma, if j < STMT_LANES { ZERO } else { va }]);
        entries.push(LoadedPub { addr: base(aa), m: base(ma), val: va });
    }
    let pd = sponge_addrs(b, &words);
    for l in 0..RATE {
        let d0 = base(sh.ds[0][l]);
        let d10 = b.sub(base(sh.ds[1][l]), d0);
        let d20 = b.sub(base(sh.ds[2][l]), d0);
        let t = b.mul_add(k0, d10, d0);
        let want = b.mul_add(k1, d20, t);
        b.assert_eq(base(pd[l]), want);
    }
    let d = emit_ssa_child_loaded(b, nvars, &entries, &gate, kid.map(|k| &k.proof[..]), &mut WhirOnSsa)?;
    let pre = |p: &[Ext]| -> Vec<Ext> { [k1, k0].into_iter().chain(p.iter().copied()).collect() };
    claims.push(Claim { point: pre(&d.x), cols: Cols::Bus, vals: d.fx.clone() });
    claims.push(Claim { point: pre(&d.r), cols: Cols::All, vals: d.fr.clone() });
    Ok(())
}

/// Fold a node's claims into its one, and write its statement `io ‖ D0 ‖ D1 ‖ D2 ‖ claim digest` (public, last).
fn finish(b: &mut Builder, fam: Option<&Family>, nvars: usize, with: bool, sh: &Shared, io: &[Addr], claims: &[Claim]) -> Result<UClaim, String> {
    let f = emit_fold(b, claims, nvars + KBITS, fam.filter(|_| with).map(Family::comb))?;
    let ev = |e: &Ext| u4(b.ext_val(*e));
    let out = UClaim { y: f.y.iter().map(ev).collect(), v: f.v.iter().map(ev).collect() };
    let fl: Vec<Addr> = f.y.iter().chain(&f.v).flat_map(|e| e.0).collect();
    let cd_own = sponge_addrs(b, &fl);
    let mut own: Vec<Addr> = io.to_vec();
    for d in &sh.ds {
        own.extend_from_slice(d);
    }
    own.extend_from_slice(&cd_own);
    let vals: Vec<Fa4> = own.iter().map(|&a| if with { b.val(a) } else { Fa4::ZERO }).collect();
    let st = b.public_vals(&vals);
    for l in 0..own.len() {
        b.assert_eq(base(own[l]), base(st[l]));
    }
    Ok(out)
}

fn load_shared(b: &mut Builder, fam: Option<&Family>, with: bool) -> Shared {
    let ds = (0..KINDS)
        .map(|i| {
            let v = fam.filter(|_| with).map_or([Fa4::ZERO; RATE], |f| f.digests[i]);
            b.load(&v).try_into().expect("eight lanes")
        })
        .collect();
    Shared { ds }
}

/// The leaf's builder in the family: the structural leaf plus the four statement lanes it does not read.
fn leaf_u_builder(shape: Shape, vals: Option<(&LeafVals<'_>, &[Fa4], &Lanes)>) -> Result<(Builder, Lanes, Lanes, Lanes, Vec<bool>), String> {
    let (k, t, o, sp) = shape;
    let (mut b, list, cs, ce, fe) = crate::absence_ssa::span_leaf_builder(k, t, o, sp, vals.map(|v| v.0))?;
    let ds: Vec<Fa4> = vals.map_or(vec![Fa4::ZERO; KINDS * RATE], |v| v.1.to_vec());
    let cd = vals.map_or([Fa4::ZERO; RATE], |v| *v.2);
    b.public_vals(&ds);
    b.public_vals(&cd);
    Ok((b, list, cs, ce, fe))
}

fn abs_io_addrs(b: &mut Builder, nd: &[Addr], s: &[Addr], e: &[Addr], f0: &[Addr], f1: &[Addr]) -> [Addr; RATE] {
    let w: Vec<Addr> = nd.iter().chain(s).chain(e).chain(f0).chain(f1).copied().collect();
    sponge_addrs(b, &w)
}

/// The merge's builder: two children of the family whose spans and bits meet.
fn merge_u_builder(fam: Option<&Family>, shape: Shape, nvars: usize, pub_len: usize, kids: Option<[&UProof; 2]>) -> Result<(Builder, UClaim), String> {
    let k = shape.0;
    let mut b = Builder::new();
    let with = kids.is_some();
    let zero = [Fa4::ZERO; RATE];
    let none = vec![false; k];
    let lb = |v: &[bool]| v.iter().map(|&x| bit(x)).collect::<Vec<_>>();
    let (nd, a_s, mid, b_e, fa, fm, fb) = match kids {
        Some([l, r]) => (
            lanes_of_u32(&l.nfs_d).ok_or("non-canonical")?,
            lanes_of_u32(&l.c_start).ok_or("non-canonical")?,
            lanes_of_u32(&l.c_end).ok_or("non-canonical")?,
            lanes_of_u32(&r.c_end).ok_or("non-canonical")?,
            l.f_start.clone(),
            l.f_end.clone(),
            r.f_end.clone(),
        ),
        None => (zero, zero, zero, zero, none.clone(), none.clone(), none),
    };
    let sh = load_shared(&mut b, fam, with);
    let nda = b.load(&nd);
    let asa = b.load(&a_s);
    let mida = b.load(&mid);
    let bea = b.load(&b_e);
    let faa = b.load(&lb(&fa));
    let fma = b.load(&lb(&fm));
    let fba = b.load(&lb(&fb));
    let mut claims = Vec::new();
    let io_l = abs_io_addrs(&mut b, &nda, &asa, &mida, &faa, &fma);
    emit_family_child(&mut b, fam, nvars, pub_len, &sh, io_l, kids.map(|k| k[0]), &mut claims)?;
    let io_r = abs_io_addrs(&mut b, &nda, &mida, &bea, &fma, &fba);
    emit_family_child(&mut b, fam, nvars, pub_len, &sh, io_r, kids.map(|k| k[1]), &mut claims)?;
    let io_own = abs_io_addrs(&mut b, &nda, &asa, &bea, &faa, &fba);
    let c = finish(&mut b, fam, nvars, with, &sh, &io_own, &claims)?;
    Ok((b, c))
}

/// The reshape's values: the child, its list, the new list, which slots are replaced.
struct ReshapeVals<'a> {
    child: &'a UProof,
    old: &'a [Entry],
    new: &'a [Entry],
    replaced: &'a [bool],
}

/// The reshape's builder: one child over `old`, restated over `new` where a slot is either kept (the same entry, its bits)
/// or replaced (any entry, its bits forced to zero at both ends).
fn reshape_u_builder(fam: Option<&Family>, shape: Shape, nvars: usize, pub_len: usize, vals: Option<&ReshapeVals<'_>>) -> Result<(Builder, UClaim), String> {
    let k = shape.0;
    let mut b = Builder::new();
    let with = vals.is_some();
    let zero = [Fa4::ZERO; RATE];
    let words_of = |es: &[Entry]| -> Vec<Fa4> { es.iter().flat_map(|(n, l)| n.iter().chain(l.iter()).copied()).collect() };
    if let Some(v) = vals {
        if v.old.len() != k || v.new.len() != k || v.replaced.len() != k || v.child.nfs_d != lanes_u32(&nfs_digest(v.old)) {
            return Err("the reshape's values are not its kind's".into());
        }
    }
    let sh = load_shared(&mut b, fam, with);
    let oa = b.load(&vals.map_or(vec![Fa4::ZERO; k * 2 * RATE], |v| words_of(v.old)));
    let na = b.load(&vals.map_or(vec![Fa4::ZERO; k * 2 * RATE], |v| words_of(v.new)));
    let old_d = sponge_addrs(&mut b, &oa);
    let new_d = sponge_addrs(&mut b, &na);
    let cs = vals.map_or(Some(zero), |v| lanes_of_u32(&v.child.c_start)).ok_or("non-canonical")?;
    let ce = vals.map_or(Some(zero), |v| lanes_of_u32(&v.child.c_end)).ok_or("non-canonical")?;
    let csa = b.load(&cs);
    let cea = b.load(&ce);
    let fsa = b.load(&vals.map_or(vec![Fa4::ZERO; k], |v| v.child.f_start.iter().map(|&x| bit(x)).collect()));
    let fea = b.load(&vals.map_or(vec![Fa4::ZERO; k], |v| v.child.f_end.iter().map(|&x| bit(x)).collect()));
    let mut fs_new: Vec<Addr> = Vec::with_capacity(k);
    let mut fe_new: Vec<Addr> = Vec::with_capacity(k);
    for j in 0..k {
        let s = b.load_ext(Ea4::from(bit(vals.is_some_and(|v| v.replaced[j]))));
        let ns = b.sub(Ext::ZERO, s);
        b.assert_mul_add_zero(s, s, ns);
        let keep = b.sub(Ext::ONE, s);
        // a kept slot is the same entry, lane for lane
        for l in 0..2 * RATE {
            let d = b.sub(base(na[j * 2 * RATE + l]), base(oa[j * 2 * RATE + l]));
            b.assert_mul_add_zero(keep, d, Ext::ZERO);
        }
        // its bits: kept, or zero
        fs_new.push(b.mul(keep, base(fsa[j])).0[0]);
        fe_new.push(b.mul(keep, base(fea[j])).0[0]);
    }
    let mut claims = Vec::new();
    let io_c = abs_io_addrs(&mut b, &old_d, &csa, &cea, &fsa, &fea);
    emit_family_child(&mut b, fam, nvars, pub_len, &sh, io_c, vals.map(|v| v.child), &mut claims)?;
    let io_own = abs_io_addrs(&mut b, &new_d, &csa, &cea, &fs_new, &fe_new);
    let c = finish(&mut b, fam, nvars, with, &sh, &io_own, &claims)?;
    Ok((b, c))
}

/// The wrapper's values.
struct WrapVals<'a> {
    entries: &'a [Entry],
    j: usize,
    carrier: &'a UProof,
    binder: Lanes,
    blind: Lanes,
}

fn lanes_digest(l: &Lanes) -> usdm_decider::poseidon2_compress::Digest {
    core::array::from_fn(|i| u64::from(l[i].as_canonical_u32()))
}
fn digest_lanes(d: &usdm_decider::poseidon2_compress::Digest) -> Lanes {
    core::array::from_fn(|i| Fa4::from_u64(d[i]))
}

/// The spend wrapper's builder: one family child (the list carrier), the spent entry selected by a hidden mark with its
/// created bit set, its leaf bound to the spend's member tuple by `P(P(leaf, binder), blind)`, one claim.
fn wrap_u_builder(fam: Option<&Family>, shape: Shape, nvars: usize, pub_len: usize, vals: Option<&WrapVals<'_>>) -> Result<(Builder, UClaim), String> {
    let k = shape.0;
    let mut b = Builder::new();
    let with = vals.is_some();
    let zero = [Fa4::ZERO; RATE];
    let (nf_v, leaf_v, lc_v, ce_v, binder_v, blind_v) = match vals {
        Some(v) => {
            let (nf, leaf) = *v.entries.get(v.j).ok_or("the spent entry is not in the list")?;
            let inner = usdm_decider::poseidon2_compress::compress(&lanes_digest(&leaf), &lanes_digest(&v.binder));
            let lc = usdm_decider::poseidon2_compress::compress(&inner, &lanes_digest(&v.blind));
            (nf, leaf, digest_lanes(&lc), lanes_of_u32(&v.carrier.c_end).ok_or("non-canonical")?, v.binder, v.blind)
        }
        None => (zero, zero, zero, zero, zero, zero),
    };
    let sh = load_shared(&mut b, fam, with);
    let nfa = b.load(&nf_v);
    let bda = b.load(&binder_v);
    let lca = b.load(&lc_v);
    let cea = b.load(&ce_v);
    let ew: Vec<Fa4> = vals.map_or(vec![Fa4::ZERO; k * 2 * RATE], |v| v.entries.iter().flat_map(|(n, l)| n.iter().chain(l.iter()).copied()).collect());
    let ea = b.load(&ew);
    let list_d = sponge_addrs(&mut b, &ea);
    let cs_v = vals.map_or(Some(zero), |v| lanes_of_u32(&v.carrier.c_start)).ok_or("non-canonical")?;
    let csa = b.load(&cs_v);
    let fsa = b.load(&vals.map_or(vec![Fa4::ZERO; k], |v| v.carrier.f_start.iter().map(|&x| bit(x)).collect()));
    let fea = b.load(&vals.map_or(vec![Fa4::ZERO; k], |v| v.carrier.f_end.iter().map(|&x| bit(x)).collect()));
    let la = b.load(&leaf_v);
    // ⭐ A-F114 — ONE SLOT, NO SELECTOR (the admitted shape is one entry, `ADMITTED_SPEND_SHAPE.0 == 1`): the spent entry can
    // only be entry 0, so the selector the k-slot form proves (`m_i` boolean, `Σ m_i = 1`, the selected lanes) is the
    // constant 1, and what it proves is exactly: entry 0's nullifier and leaf are the statement's, and its end bit is set.
    // MEASURED why it matters (u7, 2026-11-22): the k-slot form laid 16,386 rows, two over the 2^14 a blinded wrapper must
    // fit in to stay inside 2^15, so the wrapper was laid at 2^16 (prove 6.69 s); ~55 ALU operations become 17.
    if k == 1 {
        for l in 0..RATE {
            b.assert_eq(base(ea[l]), base(nfa[l]));
            b.assert_eq(base(ea[RATE + l]), base(la[l]));
        }
        b.assert_eq(base(fea[0]), Ext::ONE);
        if vals.is_some_and(|v| v.j != 0) {
            return Err("a one-slot list spends only its entry 0".into());
        }
    }
    let mut msum = Ext::ZERO;
    let mut acc_nf = [Ext::ZERO; RATE];
    let mut acc_leaf = [Ext::ZERO; RATE];
    let mut acc_bit = Ext::ZERO;
    for i in 0..k {
        if k == 1 {
            break; // the one-slot form above
        }
        let m = b.load_ext(Ea4::from(bit(vals.is_some_and(|v| v.j == i))));
        let nm = b.sub(Ext::ZERO, m);
        b.assert_mul_add_zero(m, m, nm);
        msum = b.add(msum, m);
        for l in 0..RATE {
            let dn = b.sub(base(ea[i * 2 * RATE + l]), base(nfa[l]));
            acc_nf[l] = b.mul_add(m, dn, acc_nf[l]);
            let dl = b.sub(base(ea[i * 2 * RATE + RATE + l]), base(la[l]));
            acc_leaf[l] = b.mul_add(m, dl, acc_leaf[l]);
        }
        let unset = b.sub(Ext::ONE, base(fea[i]));
        acc_bit = b.mul_add(m, unset, acc_bit);
    }
    if k != 1 {
        b.assert_eq(msum, Ext::ONE);
        for l in 0..RATE {
            b.assert_eq(acc_nf[l], Ext::ZERO);
            b.assert_eq(acc_leaf[l], Ext::ZERO);
        }
        b.assert_eq(acc_bit, Ext::ZERO);
    }
    let bla = b.load(&blind_v);
    let e8 = |a: &[Addr]| -> [Ext; 8] { core::array::from_fn(|i| base(a[i])) };
    let inner = crate::prod_perm_ssa::production_compress(&mut b, e8(&la), e8(&bda));
    let lc = crate::prod_perm_ssa::production_compress(&mut b, inner, e8(&bla));
    for l in 0..RATE {
        b.assert_eq(lc[l], base(lca[l]));
    }
    let mut claims = Vec::new();
    let io_c = abs_io_addrs(&mut b, &list_d, &csa, &cea, &fsa, &fea);
    emit_family_child(&mut b, fam, nvars, pub_len, &sh, io_c, vals.map(|v| v.carrier), &mut claims)?;
    let sw: Vec<Addr> = nfa.iter().chain(bda.iter()).chain(lca.iter()).chain(cea.iter()).copied().collect();
    let io_own = sponge_addrs(&mut b, &sw);
    let c = finish(&mut b, fam, nvars, with, &sh, &io_own, &claims)?;
    Ok((b, c))
}

/// ⭐ A-F114 — a family's shape: `(entries, tag chunks, output chunks, records a leaf spans)`. A leaf lays `s` records of
/// one `(t, o)` (`absence_ssa::span_leaf_builder`); MEASURED (`absence_ssa::tests::s2`): rows ≈ 2^11 × entries × records,
/// so at entries × records = 16 a leaf fills the family's 2^15 rows and a carrier proves one leaf and one merge a span.
pub type Shape = (usize, usize, usize, usize);

fn family_cache() -> &'static std::sync::Mutex<std::collections::HashMap<Shape, std::sync::Arc<Family>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<Shape, std::sync::Arc<Family>>>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// The statement-only builders of the three programs at `(n, p)`.
fn builders(shape: Shape, n: usize, p: usize) -> Result<Vec<Builder>, String> {
    let (lb, ..) = leaf_u_builder(shape, None)?;
    let (mb, _) = merge_u_builder(None, shape, n, p, None)?;
    let (rb, _) = reshape_u_builder(None, shape, n, p, None)?;
    Ok(vec![lb, mb, rb])
}

/// The family of `shape = (entries, tag chunks, output chunks)`: its three programs iterated to ONE shape (the merge and
/// the reshape verify a child of the family's own shape), then their digests, the leaf's claim and the wrapper.
pub fn family(shape: Shape) -> Result<std::sync::Arc<Family>, String> {
    if let Some(f) = family_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&shape).cloned() {
        return Ok(f);
    }
    let (mut n, mut p) = (crate::ssa::MIN_NVARS, STMT_LANES);
    for _ in 0..8 {
        let bs = builders(shape, n, p)?;
        let mut n2 = n;
        let mut p2 = STMT_LANES;
        for bl in &bs {
            let (_, pr) = crate::ssa::lay(bl)?;
            n2 = n2.max(pr.nvars);
            p2 = p2.max(pr.public.len());
        }
        if n2 == n && p2 <= p {
            let progs: Vec<Program> = bs.iter().map(|bl| lay_uniform(bl, n, p).map(|x| x.1)).collect::<Result<_, _>>()?;
            let digests: Vec<Lanes> = progs.iter().map(pub_digest).collect();
            let empty_prog = Program { rows: 0, nvars: 0, fixed: Vec::new(), public: Vec::new(), statement: Vec::new(), quarter: false };
            let mut fam = Family { shape, nvars: n, pub_len: p, progs, digests, leaf_claim: UClaim { y: Vec::new(), v: Vec::new() }, wrap: empty_prog, comb: std::sync::OnceLock::new() };
            let y0 = vec![Ea4::ZERO; n + KBITS];
            let v0 = fam.comb_at(&y0).ok_or("the zero point")?;
            fam.leaf_claim = UClaim { y: y0.iter().map(|e| u4(*e)).collect(), v: v0.iter().map(|e| u4(*e)).collect() };
            let (wb, _) = wrap_u_builder(None, shape, n, p, None)?;
            fam.wrap = lay_wrap(&wb)?.1;
            let a = std::sync::Arc::new(fam);
            family_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(shape, a.clone());
            return Ok(a);
        }
        n = n2;
        p = p2;
    }
    Err("the family's shape does not reach a fixpoint in 8 rounds".into())
}

fn prove_node(b: &Builder, fam: &Family) -> Option<Vec<u8>> {
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay_uniform(b, fam.nvars, fam.pub_len).ok()?;
    if prog.nvars != fam.nvars {
        return None;
    }
    let cols = crate::ssa::execute(b, &rows, &prog).ok()?;
    crate::ssa_door::prove(&prog, cols)
}

/// Prove one record of a list as a family LEAF.
#[must_use]
pub fn prove_leaf(entries: &[Entry], c_start: Lanes, f_start: &[bool], rec: &Record) -> Option<Vec<u8>> {
    prove_span(entries, c_start, f_start, std::slice::from_ref(rec))
}

/// ⭐ A-F114 — prove a leaf over `recs` (one shape each, in chain order) in the family of `(k, t, o, recs.len())`.
#[must_use]
pub fn prove_span(entries: &[Entry], c_start: Lanes, f_start: &[bool], recs: &[Record]) -> Option<Vec<u8>> {
    let first = recs.first()?;
    if recs.iter().any(|r| r.tags.len() != first.tags.len() || r.outs.len() != first.outs.len()) {
        return None;
    }
    let shape = (entries.len(), first.tags.len(), first.outs.len(), recs.len());
    let fam = family(shape).ok()?;
    let v = LeafVals { entries, c_start, f_start, recs, force_created: None };
    let cd = fam.leaf_claim.digest();
    let dw = fam.digest_words();
    let (b, list, cs, ce, fe) = leaf_u_builder(shape, Some((&v, &dw, &cd))).ok()?;
    let proof = prove_node(&b, &fam)?;
    postcard::to_allocvec(&UProof { proof, kind: LEAF, shape, nfs_d: lanes_u32(&list), c_start: lanes_u32(&cs), c_end: lanes_u32(&ce), f_start: f_start.to_vec(), f_end: fe, claim: fam.leaf_claim.clone() }).ok()
}

/// Merge two family proofs whose spans and bits meet, with the ONE merge program.
#[must_use]
pub fn prove_merge(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    let l: UProof = postcard::from_bytes(left).ok()?;
    let r: UProof = postcard::from_bytes(right).ok()?;
    if l.shape != r.shape || l.nfs_d != r.nfs_d || l.c_end != r.c_start || l.f_end != r.f_start {
        return None;
    }
    let fam = family(l.shape).ok()?;
    let (b, claim) = merge_u_builder(Some(&fam), l.shape, fam.nvars, fam.pub_len, Some([&l, &r])).ok()?;
    let proof = prove_node(&b, &fam)?;
    postcard::to_allocvec(&UProof { proof, kind: MERGE, shape: l.shape, nfs_d: l.nfs_d, c_start: l.c_start, c_end: r.c_end, f_start: l.f_start, f_end: r.f_end, claim }).ok()
}

/// Restate a carrier over `old` as one over `new`, where the `replaced` slots take new entries uncreated at both ends (a
/// note joins an empty slot before the record that makes it; a spent note's slot is cleared). Kept slots must be equal.
#[must_use]
pub fn prove_reshape(child: &[u8], old: &[Entry], new: &[Entry], replaced: &[bool]) -> Option<Vec<u8>> {
    let c: UProof = postcard::from_bytes(child).ok()?;
    let fam = family(c.shape).ok()?;
    if old.len() != new.len() || old.len() != replaced.len() || old.iter().zip(new).zip(replaced).any(|((o, n), r)| !*r && o != n) {
        return None; // a kept slot that changed: no statement covers it
    }
    let v = ReshapeVals { child: &c, old, new, replaced };
    let (b, claim) = reshape_u_builder(Some(&fam), c.shape, fam.nvars, fam.pub_len, Some(&v)).ok()?;
    let proof = prove_node(&b, &fam)?;
    let fs: Vec<bool> = c.f_start.iter().zip(replaced).map(|(f, r)| *f && !*r).collect();
    let fe: Vec<bool> = c.f_end.iter().zip(replaced).map(|(f, r)| *f && !*r).collect();
    postcard::to_allocvec(&UProof { proof, kind: RESHAPE, shape: c.shape, nfs_d: lanes_u32(&nfs_digest(new)), c_start: c.c_start, c_end: c.c_end, f_start: fs, f_end: fe, claim }).ok()
}

/// ⭐ THE CARRIER DOOR: the family proof `bytes` proves the list `list_d` absent, from `c_start` (bits `f_start`) to `c_end`
/// (bits `f_end`), from each entry's making on. Native: the one claim against the stacked table, the statement with the
/// family's real program digests (which bind every child's constants at every level below), the SSA door.
/// ⛔ A-F114 (2026-11-22): the door NAMES the one shape it admits (`shape`), and a proof of any other shape is refused
/// BEFORE its family is built. Without it the proof's own bytes chose the shape: a hostile `(10^6, …)` made a verifying
/// node lay that family's programs (unbounded work, §9.6 (5)) and keep them in the family cache for ever (unbounded
/// memory, the NO GROWTH pillar), one entry per shape a peer cared to name.
#[must_use]
pub fn verify(bytes: &[u8], shape: Shape, list_d: &Lanes, c_start: &Lanes, f_start: &[bool], c_end: &Lanes, f_end: &[bool]) -> bool {
    let Ok(u) = postcard::from_bytes::<UProof>(bytes) else { return false };
    if u.shape != shape {
        return false; // a shape this door does not admit: no family is built for it
    }
    let Ok(fam) = family(u.shape) else { return false };
    if usize::from(u.kind) >= KINDS || f_start.len() != u.shape.0 || f_end.len() != u.shape.0 {
        return false;
    }
    if u.nfs_d != lanes_u32(list_d) || u.c_start != lanes_u32(c_start) || u.c_end != lanes_u32(c_end) || u.f_start != f_start || u.f_end != f_end {
        return false;
    }
    if !claim_holds(&fam, &u.claim) {
        return false;
    }
    let io = abs_io(list_d, c_start, c_end, f_start, f_end);
    let svals: Vec<Fa4> = io.iter().copied().chain(fam.digest_words()).chain(u.claim.digest()).collect();
    let prog = &fam.progs[usize::from(u.kind)];
    prog.statement.len() == STMT_LANES && crate::ssa_door::verify(&u.proof, &stated(prog, &svals))
}

fn claim_holds(fam: &Family, c: &UClaim) -> bool {
    if c.y.len() != fam.nvars + KBITS || c.v.len() != NFIXED {
        return false;
    }
    let y: Vec<Ea4> = c.y.iter().map(e4).collect();
    let v: Vec<Ea4> = c.v.iter().map(e4).collect();
    fam.comb_at(&y) == Some(v)
}

/// ⭐ A-F114 — THE WRAPPER IS PUBLISHED, SO IT IS BLINDED (DIGITAL CASH; audit 17:40 → 18:30). The wrapper is the one proof
/// of a spend every node sees, and its witness holds the spent leaf, its binder and blind, and the list. The SSA door
/// opens unmasked evaluations of the committed table (`ssa_door.rs`: `slot_at_x`, the zerocheck's row at `r`, GKR, the
/// WHIR opening), so the table is laid one variable TALLER than `lay` gives ([`lay_wrap`]): every laid row sits in one
/// half, and every committed cell no laid row occupies is fresh OS randomness
/// ([`blind_padding`]). BORROWED: the spend carrier's blinded rows (`committed_air::prove_air_blinded_bytes`, §BE-1/§BI:
/// "doubles the height, fills the new half with fresh OS randomness"). It costs no constraint: every SSA law is
/// multiplied by a fixed selector and every bus leaf's numerator is a fixed multiplicity (`ssa::ssa_residuals_with`,
/// `ssa::bus_leaves`), all zero on a padding row, so a random padding row is read by nothing. Prover and verifier lay the
/// same program (a lay is a function of the operation list alone); rows are bit-reversed (`ssa::row_at`), so the random
/// half is the one whose LAST row bit is 1. cons: the wrapper's table doubles (2^15 → 2^16 rows
/// at `SPEND_SHAPE`), so its prove time roughly doubles (MEASURED by u7) and its opening gains one round. The carrier's
/// leaves and merges never leave the spender and stay unblinded. NOT CONFIRMED: that blinded rows make the GKR bus's
/// layer claims simulatable (§BE-1 accepted them for the row-local zerocheck; the SSA bus is GKR).
fn lay_wrap(b: &Builder) -> Result<(Vec<crate::ssa::RowPlan>, Program), String> {
    // the smallest table whose QUARTER holds every laid row, placed by `ssa::place_row` (a function of the operation list alone)
    crate::ssa::lay_at_quarter(b, crate::ssa::MIN_NVARS)
}

/// Fill every committed cell of every row NO laid row occupies with fresh OS randomness. A laid row `li` sits at
/// `ssa::row_at(li, nvars)` (bit-reversed), never at `li`: MEASURED 2026-11-22, randomizing indices past `real_rows`
/// overwrote real rows and the door refused every wrapper (u2, u3, u7). Laid one variable taller ([`lay_wrap`]), every
/// `li < 2^(nvars-1)` reverses to an EVEN position, so the whole odd half (last row bit 1) is randomness: the §BE-1 split
/// along one variable. FAIL-CLOSED: no entropy, no proof (a wrapper that looks blinded and is not would leak as much as an
/// unblinded one, with nobody looking).
fn blind_padding(cols: &mut [Vec<Fa4>], real_rows: usize, nvars: usize) -> Option<()> {
    use rand::{RngExt, SeedableRng};
    let t = 1usize << nvars;
    if cols.iter().any(|c| c.len() != t) {
        return None;
    }
    if 4 * real_rows > t {
        return None; // the real rows must fit the blinded quarter
    }
    let mut occupied = vec![false; t];
    for li in 0..real_rows {
        occupied[crate::ssa::place_row(li, nvars, true)] = true;
    }
    // every laid row in the quarter whose first and last row bits are 0 (`ssa::place_row`; the row_at bit reversal within it)
    if (0..t).any(|r| occupied[r] && (r % 2 == 1 || r >= t / 2)) {
        return None;
    }
    let mut rng = rand::rngs::SmallRng::try_from_rng(&mut rand::rngs::SysRng::default()).ok()?;
    for c in cols.iter_mut() {
        for (r, v) in c.iter_mut().enumerate() {
            if !occupied[r] {
                *v = Fa4::from_u64(u64::from(rng.random::<u32>()));
            }
        }
    }
    Some(())
}

/// A spend wrapper over a family carrier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct USpend {
    pub proof: Vec<u8>,
    pub shape: Shape,
    pub claim: UClaim,
}

/// Prove the spend of entry `j` from the family carrier `carrier` (its end bit for `j` set).
#[must_use]
pub fn prove_spend(entries: &[Entry], j: usize, carrier: &[u8], binder: Lanes, blind: Lanes) -> Option<Vec<u8>> {
    let c: UProof = postcard::from_bytes(carrier).ok()?;
    if c.nfs_d != lanes_u32(&nfs_digest(entries)) || !c.f_end.get(j).copied().unwrap_or(false) {
        return None;
    }
    let fam = family(c.shape).ok()?;
    let v = WrapVals { entries, j, carrier: &c, binder, blind };
    let (b, claim) = wrap_u_builder(Some(&fam), c.shape, fam.nvars, fam.pub_len, Some(&v)).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay_wrap(&b).ok()?;
    let mut cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    blind_padding(&mut cols, rows.len(), prog.nvars)?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    postcard::to_allocvec(&USpend { proof, shape: c.shape, claim }).ok()
}

/// ⭐ THE SPEND DOOR: the note behind `leaf_commit` (under `binder`) was made in a record of this chain and its nullifier
/// (tag lanes `nf`) is a tag of no record from its making to `c_end`. One claim, the statement with the real digests, the
/// wrapper's SSA proof. ⛔ A-F114: `shape` is the one shape the door admits, checked before any family is built (see
/// [`verify`]).
#[must_use]
pub fn verify_spend(bytes: &[u8], shape: Shape, nf: &Lanes, binder: &Lanes, leaf_commit: &Lanes, c_end: &Lanes) -> bool {
    let Ok(s) = postcard::from_bytes::<USpend>(bytes) else { return false };
    if s.shape != shape {
        return false; // a shape this door does not admit: no family is built for it
    }
    let Ok(fam) = family(s.shape) else { return false };
    if !claim_holds(&fam, &s.claim) {
        return false;
    }
    let io = spend_io(nf, binder, leaf_commit, c_end);
    let svals: Vec<Fa4> = io.iter().copied().chain(fam.digest_words()).chain(s.claim.digest()).collect();
    fam.wrap.statement.len() == STMT_LANES && crate::ssa_door::verify(&s.proof, &stated(&fam.wrap, &svals))
}

/// The chain value a record steps to.
#[must_use]
pub fn step(c: &Lanes, rec: &Record) -> Option<Lanes> {
    let mut c = *c;
    for (items, aux) in rec.tags.iter().chain(&rec.outs) {
        c = chain_step(&c, items, aux)?;
    }
    Some(c)
}

/// The lanes of an extension value.
#[must_use]
pub fn ext_lanes(e: Ea4) -> [Fa4; 4] {
    let s: &[Fa4] = BasedVectorSpace::<Fa4>::as_basis_coefficients_slice(&e);
    [s[0], s[1], s[2], s[3]]
}

/// An EMPTY slot of a fixed-length list: a domain image never a record's output (its leaf is a sponge of a domain word, a
/// real leaf is a note commitment's), so it is never created and never checked. One per slot index, so a list's empty
/// slots are distinct entries.
#[must_use]
pub fn empty_entry(slot: u64) -> Entry {
    let w = |x: u32| Fa4::from_u32(x);
    let nf = sponge_words(&[w(0x454D_5054), w(0x594E_4631), w((slot & 0x7FFF_FFFF) as u32), w(((slot >> 31) & 0x7FFF_FFFF) as u32)]);
    let leaf = sponge_words(&[w(0x454D_5054), w(0x594C_4631), w((slot & 0x7FFF_FFFF) as u32), w(((slot >> 31) & 0x7FFF_FFFF) as u32)]);
    (nf, leaf)
}

/// The list digest.
#[must_use]
pub fn list_digest(entries: &[Entry]) -> Lanes {
    nfs_digest(entries)
}

// TWO-PARTY-REVIEWED: a pure function of the records and the list; the cross-party claim is the node door's (audit 2c).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::absence_ssa::end_aux;

    fn lanes(seed: u64) -> Lanes {
        core::array::from_fn(|i| Fa4::from_u32(((seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919 + 1)) % 2_130_706_433) as u32))
    }
    fn rec(i: u64) -> Record {
        let items = |s: u64| (0..crate::absence_ssa::CHUNK_TAGS as u64).map(|t| lanes(s * 1000 + t + 1)).collect::<Vec<_>>();
        Record { tags: vec![(items(i), [Fa4::ZERO; RATE])], outs: vec![(items(i + 500), end_aux(i))] }
    }
    /// ⭐ A-F114 — MEASURE real proving at the CANONICAL record shape: 8 tag chunks (256 padded tags) and 8 output chunks
    /// (the last END), over a 16-slot list: the family build, two leaves and one merge, timed. Decides the carrier's pace cap
    /// (the per-note cost per record). Proves for real, so it takes tens of seconds.
    #[test]
    fn u5_time_a_canonical_leaf_and_merge_at_sixteen_slots() {
        let canon = |i: u64| -> Record {
            let items = |s: u64| (0..crate::absence_ssa::CHUNK_TAGS as u64).map(|t| lanes(s * 100_000 + t + 1)).collect::<Vec<_>>();
            let tags = (0..8u64).map(|c| (items(i * 100 + c), [Fa4::ZERO; RATE])).collect();
            let outs = (0..8u64)
                .map(|c| (items(i * 100 + 50 + c), if c == 7 { end_aux(i) } else { crate::absence_ssa::out_aux() }))
                .collect();
            Record { tags, outs }
        };
        let slots: Vec<Entry> = (0..16u64).map(empty_entry).collect();
        let f = vec![false; 16];
        let (r1, r2) = (canon(1), canon(2));
        let t0 = std::time::Instant::now();
        let fam = family((16, 8, 8, 1)).expect("the family builds at the canonical shape");
        eprintln!("[u5] family at (16, 8, 8, 1): 2^{} rows, built in {:?}", fam.nvars, t0.elapsed());
        let c0 = lanes(1);
        let t1 = std::time::Instant::now();
        let l1 = prove_leaf(&slots, c0, &f, &r1).expect("leaf 1 proves");
        let d1 = t1.elapsed();
        let c1 = step(&c0, &r1).expect("step");
        let t2 = std::time::Instant::now();
        let l2 = prove_leaf(&slots, c1, &f, &r2).expect("leaf 2 proves");
        let d2 = t2.elapsed();
        let t3 = std::time::Instant::now();
        let m = prove_merge(&l1, &l2).expect("the merge proves");
        let d3 = t3.elapsed();
        eprintln!("[u5] leaf {d1:?}, leaf {d2:?}, merge {d3:?}; merged proof {} B", m.len());
        assert!(!m.is_empty());
    }

    /// ⭐ A-F114 — U7, THE PRICE OF ONE SPEND AT THE ADMITTED SHAPE `(1, 8, 8, 16)` (`canon_chain::SPEND_SHAPE`): one note
    /// made in the first of sixteen canonical records, its span leaf, and its wrapper, each timed. The wrapper's time is the
    /// wallet's spend latency after its span closes and the per-cover price of a DefiSlots batch (audit, 17:20). The door
    /// accepts it at its shape and refuses it at any other.
    #[test]
    fn u7_time_a_span_leaf_and_its_spend_at_the_admitted_shape() {
        let canon = |i: u64| -> Record {
            let items = |s: u64| (0..crate::absence_ssa::CHUNK_TAGS as u64).map(|t| lanes(s * 100_000 + t + 1)).collect::<Vec<_>>();
            let tags = (0..8u64).map(|c| (items(i * 100 + c), [Fa4::ZERO; RATE])).collect();
            let outs = (0..8u64)
                .map(|c| (items(i * 100 + 50 + c), if c == 7 { end_aux(i) } else { crate::absence_ssa::out_aux() }))
                .collect();
            Record { tags, outs }
        };
        let rs: Vec<Record> = (1..=16u64).map(canon).collect();
        let e = vec![(lanes(9_999_991), rs[0].outs[0].0[3])];
        let c0 = lanes(1);
        let mut c = c0;
        for r in &rs {
            c = step(&c, r).expect("step");
        }
        let t0 = std::time::Instant::now();
        let fam = family((1, 8, 8, 16)).expect("the family builds at the admitted shape");
        eprintln!("[u7] family at (1, 8, 8, 16): 2^{} rows, wrapper 2^{} ({} laid rows), built in {:?}", fam.nvars, fam.wrap.nvars, fam.wrap.rows, t0.elapsed());
        let t1 = std::time::Instant::now();
        let leaf = prove_span(&e, c0, &[false], &rs).expect("the span proves");
        let d1 = t1.elapsed();
        let (binder, blind) = (lanes(60), lanes(61));
        let t2 = std::time::Instant::now();
        let w = prove_spend(&e, 0, &leaf, binder, blind).expect("the note spends");
        let d2 = t2.elapsed();
        let lc = crate::absence_ssa::leaf_commit(&e[0].1, &binder, &blind);
        let t3 = std::time::Instant::now();
        assert!(verify_spend(&w, (1, 8, 8, 16), &e[0].0, &binder, &lc, &c), "the door accepts the spend at its shape");
        let d3 = t3.elapsed();
        assert!(!verify_spend(&w, (1, 8, 8, 1), &e[0].0, &binder, &lc, &c), "another shape is refused");
        // where the wrapper's rows come from (the SSA width audit, 2026-11-22 23:10): its operations by kind
        {
            let cp: UProof = postcard::from_bytes(&leaf).unwrap();
            let v = WrapVals { entries: &e, j: 0, carrier: &cp, binder, blind };
            let (wb, _) = wrap_u_builder(Some(&fam), fam.shape, fam.nvars, fam.pub_len, Some(&v)).expect("the wrapper builds");
            let count = |f: &dyn Fn(&crate::ssa::Op) -> bool| wb.ops.iter().filter(|o| f(o)).count();
            let perms = count(&|o| matches!(o, crate::ssa::Op::Perm { .. }));
            let comps = count(&|o| matches!(o, crate::ssa::Op::Comp { .. }));
            let alus = count(&|o| matches!(o, crate::ssa::Op::Alu(_)));
            let bits = count(&|o| matches!(o, crate::ssa::Op::Bits { .. }));
            let halves = count(&|o| matches!(o, crate::ssa::Op::Halve { .. }));
            eprintln!(
                "[u7] wrapper ops: {} ({perms} permutations, {comps} Merkle levels, {halves} halvings, {bits} bit rows, {alus} multiply-adds = {} rows' worth at {} units a row); laid {} rows",
                wb.ops.len(),
                alus.div_ceil(crate::ssa::NUNIT),
                crate::ssa::NUNIT,
                fam.wrap.rows
            );
        }
        // ⭐ BLINDED: the same spend proven twice gives two different wrappers (fresh randomness in the padding half), and
        // the door accepts both
        let w2 = prove_spend(&e, 0, &leaf, binder, blind).expect("the note spends again");
        assert_ne!(w, w2, "⛔ two wrappers of one spend are identical: the padding half is not random");
        assert!(verify_spend(&w2, (1, 8, 8, 16), &e[0].0, &binder, &lc, &c), "the door accepts the second blinded wrapper");
        eprintln!("[u7] span leaf {d1:?} ({} B), wrapper {d2:?} ({} B), verify {d3:?}", leaf.len(), w.len());
        // where the wrapper's bytes go: its SSA bundle's parts (the size lever for one proof per payment)
        let us: USpend = postcard::from_bytes(&w).unwrap();
        let sb: crate::ssa_door::SsaBundle = postcard::from_bytes(&us.proof).unwrap();
        eprintln!(
            "[u7] wrapper parts: claim {} B, bundle {} B = commitment {} + gkr {} + slot_at_x {} + fixed_at_x {} + zerocheck {} + whir opening {}",
            postcard::to_allocvec(&us.claim).unwrap().len(),
            us.proof.len(),
            postcard::to_allocvec(&sb.commitment).unwrap().len(),
            postcard::to_allocvec(&sb.gkr).unwrap().len(),
            postcard::to_allocvec(&sb.slot_at_x).unwrap().len(),
            postcard::to_allocvec(&sb.fixed_at_x).unwrap().len(),
            postcard::to_allocvec(&sb.zc).unwrap().len(),
            postcard::to_allocvec(&sb.open).unwrap().len(),
        );
    }

    /// ⭐ A-F114 — U6, THE SPAN LEAF: a leaf over two records ends at the chain value two single-record steps reach; two such
    /// spans merge into ONE family proof; a note made in the span's first record and spent in its second has NO span leaf
    /// (a carrier ends a span at its own spend's record).
    #[test]
    fn u6_a_span_leaf_follows_two_records_and_merges() {
        let e = vec![(lanes(7), lanes(70))];
        let rs: Vec<Record> = (1..=4).map(rec).collect();
        let c0 = lanes(1);
        let c2 = step(&step(&c0, &rs[0]).unwrap(), &rs[1]).unwrap();
        let s1 = prove_span(&e, c0, &[false], &rs[0..2]).expect("a span of two proves");
        let p1: UProof = postcard::from_bytes(&s1).unwrap();
        assert_eq!(p1.c_end, crate::absence_ssa::lanes_u32(&c2), "⛔ a span ended at another chain value than its two steps");
        assert_eq!(p1.shape.3, 2, "the span's shape names its two records");
        let s2 = prove_span(&e, c2, &p1.f_end, &rs[2..4]).expect("the next span proves");
        let m = prove_merge(&s1, &s2).expect("two spans merge");
        assert!(!m.is_empty());
        // a note made in record 1 of a span and spent in its record 2: no leaf
        let mut spent = rs[0..2].to_vec();
        let made = (lanes(90), spent[0].outs[0].0[2]);
        spent[1].tags[0].0[3] = made.0;
        assert!(prove_span(&[made], c0, &[false], &spent).is_none(), "⛔ a span leaf held a note made and spent inside it");
    }

    /// An empty slot: never a record's output, so never created, never checked.
    fn empty() -> Entry {
        (lanes(0xE0), lanes(0xE1))
    }

    /// ⭐ U1 — ONE PROGRAM, ONE CLAIM, A CONSTANT PROOF: eight records merged to depth 3; one nvars at every depth and bytes
    /// within 1 KB (the structural carrier grew ~5.8 KB a level); each root refused one record short, with another list,
    /// and with its kind changed.
    #[test]
    fn u1_one_merge_program_holds_one_claim_at_every_depth() {
        let e = vec![(lanes(7), lanes(70))];
        let nd = list_digest(&e);
        let fam = family((1, 1, 1, 1)).expect("the family reaches its fixpoint");
        eprintln!("[u1] family: nvars {}, public length {}, wrapper nvars {}", fam.nvars, fam.pub_len, fam.wrap.nvars);
        let mut c = lanes(1);
        let mut ends = vec![c];
        let mut level: Vec<Vec<u8>> = Vec::new();
        for i in 0..8u64 {
            let r = rec(i + 1);
            level.push(prove_leaf(&e, c, &[true], &r).expect("a leaf"));
            c = step(&c, &r).unwrap();
            ends.push(c);
        }
        let mut span = 1usize;
        let mut sizes = Vec::new();
        while level.len() > 1 {
            level = level.chunks(2).map(|p| prove_merge(&p[0], &p[1]).expect("meeting spans merge")).collect();
            span *= 2;
            let u: UProof = postcard::from_bytes(&level[0]).unwrap();
            assert_eq!(postcard::from_bytes::<crate::ssa_door::SsaBundle>(&u.proof).unwrap().nvars, fam.nvars, "one nvars at every depth");
            sizes.push(level[0].len());
            eprintln!("[u1] depth {}: span {span}, {} bytes", sizes.len(), level[0].len());
            assert!(verify(&level[0], (1, 1, 1, 1), &nd, &ends[0], &[true], &ends[span], &[true]), "the root of {span} records verifies");
            assert!(!verify(&level[0], (1, 1, 1, 1), &nd, &ends[0], &[true], &ends[span - 1], &[true]), "LYING PROVER: one record short");
            assert!(!verify(&level[0], (1, 1, 1, 1), &list_digest(&[(lanes(8), lanes(70))]), &ends[0], &[true], &ends[span], &[true]), "LYING PROVER: another list");
            for k in [LEAF, RESHAPE] {
                let mut flipped = u.clone();
                flipped.kind = k;
                assert!(!verify(&postcard::to_allocvec(&flipped).unwrap(), (1, 1, 1, 1), &nd, &ends[0], &[true], &ends[span], &[true]), "TAMPER: kind {k}");
            }
        }
        assert_eq!(sizes.len(), 3);
        assert!(sizes.windows(2).all(|w| w[0].abs_diff(w[1]) < 1024), "the proof is ONE size at every depth: {sizes:?}");
    }

    /// ⭐ U3 — ONE RUNNING CARRIER (the wallet's shape): every record's leaf merges into ONE carrier (never a counter of
    /// segments), a note joins its slot before the record that makes it, and a spent note's slot leaves before the record
    /// that carries its nullifier (whose leaf would otherwise not prove); the running carrier stays one size, and the
    /// remaining note still spends at the end.
    #[test]
    fn u3_one_running_carrier_follows_joins_and_clears() {
        let mut rs: Vec<Record> = (1..=5).map(rec).collect();
        let a = (lanes(81), rs[0].outs[0].0[1]);
        let bn = (lanes(82), rs[1].outs[0].0[4]);
        rs[3].tags[0].0[7] = a.0; // record 4 carries A's spend
        let mut slots = vec![empty_entry(0), empty_entry(1)];
        let mut f = vec![false, false];
        let mut c = lanes(1);
        let mut carrier: Option<Vec<u8>> = None;
        let mut sizes = Vec::new();
        for (i, r) in rs.iter().enumerate() {
            let mut new = slots.clone();
            let mut replaced = vec![false, false];
            if i == 0 {
                new[0] = a;
                replaced[0] = true;
            }
            if i == 1 {
                new[1] = bn;
                replaced[1] = true;
            }
            if i == 3 {
                // A's nullifier is a tag here: without its slot leaving, this record has no leaf
                assert!(prove_leaf(&slots, c, &f, r).is_none(), "a created note's nullifier among the tags: no leaf");
                new[0] = empty_entry(0);
                replaced[0] = true;
            }
            if replaced.iter().any(|x| *x) {
                if let Some(cc) = &carrier {
                    carrier = Some(prove_reshape(cc, &slots, &new, &replaced).expect("the reshape proves"));
                }
                for (fj, rj) in f.iter_mut().zip(&replaced) {
                    if *rj {
                        *fj = false;
                    }
                }
                slots = new;
            }
            let leaf = prove_leaf(&slots, c, &f, r).expect("the record's leaf");
            f = postcard::from_bytes::<UProof>(&leaf).unwrap().f_end;
            carrier = Some(match &carrier {
                Some(cc) => prove_merge(cc, &leaf).expect("merges into the one carrier"),
                None => leaf,
            });
            c = step(&c, r).unwrap();
            sizes.push(carrier.as_ref().unwrap().len());
        }
        eprintln!("[u3] the running carrier after each record: {sizes:?}");
        assert!(sizes[1..].windows(2).all(|w| w[0].abs_diff(w[1]) < 1024), "one size as it runs: {sizes:?}");
        assert_eq!(f, vec![false, true], "A left the list, B remains made");
        let (binder, blind) = (lanes(60), lanes(61));
        let w = prove_spend(&slots, 1, carrier.as_ref().unwrap(), binder, blind).expect("B spends");
        assert!(verify_spend(&w, (2, 1, 1, 1), &bn.0, &binder, &crate::absence_ssa::leaf_commit(&bn.1, &binder, &blind), &c), "the door accepts B's spend");
        assert!(prove_spend(&slots, 0, carrier.as_ref().unwrap(), binder, blind).is_none(), "the cleared slot spends nothing");
    }

    /// ⭐ U2 — ONE FIXED-LENGTH LIST THAT CHANGES, AND ITS SPENDS: two slots; note A (made in record 1) in slot 0, slot 1
    /// empty; B (made in record 3) is reshaped into slot 1 before record 3; the carrier merges across the reshape; both
    /// notes spend by wrappers the door accepts, and the door refuses another end, binder, leaf commitment, the list's
    /// other nullifier and a flipped byte; a reshape stating the new entry created, and one changing a kept slot, refuse.
    #[test]
    fn u2_a_reshaped_list_spends_both_notes() {
        let rs: Vec<Record> = (1..=4).map(rec).collect();
        let a = (lanes(71), rs[0].outs[0].0[2]);
        let bn = (lanes(72), rs[2].outs[0].0[5]);
        let l0 = vec![a, empty()];
        let l1 = vec![a, bn];
        let mut c = lanes(1);
        let p1 = prove_leaf(&l0, c, &[false, false], &rs[0]).expect("record 1 makes A");
        c = step(&c, &rs[0]).unwrap();
        let p2 = prove_leaf(&l0, c, &[true, false], &rs[1]).expect("record 2");
        c = step(&c, &rs[1]).unwrap();
        let m12 = prove_merge(&p1, &p2).expect("1-2");
        let rsh = prove_reshape(&m12, &l0, &l1, &[false, true]).expect("B takes the empty slot before record 3");
        assert!(verify(&rsh, (2, 1, 1, 1), &list_digest(&l1), &lanes(1), &[false, false], &c, &[true, false]), "the reshaped statement");
        assert!(!verify(&rsh, (2, 1, 1, 1), &list_digest(&l1), &lanes(1), &[false, false], &c, &[true, true]), "LYING PROVER: the new slot created");
        assert!(prove_reshape(&m12, &l0, &[(lanes(9), a.1), bn], &[false, true]).is_none(), "a kept slot cannot change");
        let p3 = prove_leaf(&l1, c, &[true, false], &rs[2]).expect("record 3 makes B");
        c = step(&c, &rs[2]).unwrap();
        let p4 = prove_leaf(&l1, c, &[true, true], &rs[3]).expect("record 4");
        c = step(&c, &rs[3]).unwrap();
        let m34 = prove_merge(&p3, &p4).expect("3-4");
        let all = prove_merge(&rsh, &m34).expect("across the reshape");
        assert!(verify(&all, (2, 1, 1, 1), &list_digest(&l1), &lanes(1), &[false, false], &c, &[true, true]), "both made in the span");
        for (j, (nf, leaf)) in l1.iter().enumerate() {
            let (binder, blind) = (lanes(40 + j as u64), lanes(50 + j as u64));
            let w = prove_spend(&l1, j, &all, binder, blind).expect("the note spends");
            let lc = crate::absence_ssa::leaf_commit(leaf, &binder, &blind);
            eprintln!("[u2] spend {j}: {} bytes", w.len());
            assert!(verify_spend(&w, (2, 1, 1, 1), nf, &binder, &lc, &c), "the door accepts note {j}'s spend");
            assert!(!verify_spend(&w, (2, 1, 1, 1), nf, &binder, &lc, &lanes(5)), "LYING PROVER: another end");
            assert!(!verify_spend(&w, (2, 1, 1, 1), nf, &lanes(33), &lc, &c), "LYING PROVER: another binder");
            assert!(!verify_spend(&w, (2, 1, 1, 1), nf, &binder, &lanes(34), &c), "LYING PROVER: another leaf commitment");
            assert!(!verify_spend(&w, (2, 1, 1, 1), &l1[1 - j].0, &binder, &lc, &c), "LYING PROVER: the list's other nullifier");
            let mut bad = w.clone();
            let n = bad.len();
            bad[n / 3] ^= 1;
            assert!(!verify_spend(&bad, (2, 1, 1, 1), nf, &binder, &lc, &c), "TAMPER: a flipped byte");
            assert!(!verify_spend(&w, (2, 1, 1, 2), nf, &binder, &lc, &c), "a shape the door does not admit is refused before its family is built");
        }
    }
}

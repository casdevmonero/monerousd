// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐ THE SOUND ABSENCE CARRIER (A-F114 phases 2a/2b, lane speed5, 2026-11-22; docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md).
//!
//! User 2026-11-22: *"the memory shouldnt be growing with time … you broke the 0(1) pillar"*. A node can stop holding the
//! spent set only when a spender carries a SOUND proof that its nullifier appears in no block since its note was made.
//! The old carrier's fold (`verify_merged_fixed_step_bytes`) verifies no inner statement (DB-213c) and rides an ADDITIVE
//! accumulator a forger can hit with Wagner's k-tree (the audit's "FOUND 2026-11-22"). This module replaces both.
//!
//! * **The chain is a HASH CHAIN** in canonical record order: `C' = sponge(C ‖ 32 items ‖ aux)` (BORROWED: Bitcoin's
//!   prev-hash). A record is its tag chunks (aux zero) then its output-leaf chunks (aux [`out_aux`]), the last one
//!   [`end_aux`]. A chain ending at the node's `C` cannot be forged backwards (a Poseidon2 preimage), so every step of a
//!   carrier ending there is a real chunk, with its real role.
//! * **A list entry is `(nf, leaf)`**: a nullifier and its note's leaf. The statement carries one CREATED bit per entry at
//!   each end. A RECORD LEAF sets an entry's bit where the prover marks the output that IS its leaf, lane for lane (an
//!   exact equality: a fixed-point combination would let a forged leaf match), and checks `nf` against every tag wherever the bit is set
//!   after the record: `(t' − n')·w = F`, `t' = Σ_l k^l·t_l`. If `t = nf` and `F = 1` no `w` exists.
//! * **A MERGE** verifies two children IN CIRCUIT (`ssa_inner::emit_ssa_child`) and shares one address for the meeting
//!   chain value and the meeting bits, so neither a gap nor a flipped bit can be stated.
//! * **The spend's wrapper** (next) requires the spent entry's bit at the carrier's end: the note was made in a real record
//!   of the span and every record after it in the span was checked. Nothing names the record or the note.
//!
//! §9.6: (1) PoW — the chain's own; (2) the proof by the SSA door, every node below in circuit; (3) value — none created;
//! (4) replay — the node accepts only a chain end its window holds and checks the records after it itself; (5) work — one
//! SSA verify plus one program MLE a kind below (≤ 2·64 kinds); (6) parity — the child door is the payment tree's (pin
//! m1); (7) scale — a constant proof, no term in the bonded set, the items in flight or height; (8) (a) a proof every node
//! checks. O1-FOOTPRINT-REVIEWED: the program cache holds one program per KIND, and a carrier meets at most 2·64 kinds.

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::fold_claims::{emit_fold, Claim, Cols};
use crate::ssa::{lay, Addr, Builder, Ext, Program, RATE, ZERO};
use crate::ssa_inner::{emit_ssa_child, ssa_gate_program, ChildShape};
use crate::tree_ssa::{e4, sponge_addrs, sponge_words, stated, u4};
use crate::verify_whir_ssa::WhirOnSsa;

/// Items (tags, or output leaves) one chain step absorbs.
pub const CHUNK_TAGS: usize = 32;
/// The largest carrier a node accepts (a bound, from the measured root size of the payment tree).
pub const ABS_MAX_BYTES: usize = 4 << 20;

/// Eight lanes, each a canonical KoalaBear element.
pub type Lanes = [Fa4; RATE];
/// A chunk: its [`CHUNK_TAGS`] items and its aux lanes (its role in the record).
pub type Chunk = (Vec<Lanes>, Lanes);
/// A list entry: a nullifier and its note's leaf.
pub type Entry = (Lanes, Lanes);

/// One record as the chain absorbs it: its tag chunks, then its output-leaf chunks (the last one carries [`end_aux`]).
#[derive(Clone, Debug)]
pub struct Record {
    pub tags: Vec<Chunk>,
    pub outs: Vec<Chunk>,
}

/// The Horner point of the INEQUALITY combinations (tag ≠ nullifier) only. Any constant is sound there: a nonzero
/// combination implies the values differ, whatever `k` is; a fixed non-base value keeps an honest unequal pair from
/// combining to zero except with probability ~2^-124. NEVER used for an equality claim: with a public `k` a forged value
/// can be solved to combine equal (four linear equations in eight unknowns).
pub(crate) fn horner_k() -> Ea4 {
    Ea4::from_basis_coefficients_fn(|i| Fa4::from_u32([0x2F6B_1D07, 0x0B5E_93A1, 0x3C41_77E5, 0x1A9D_0C63][i]))
}

/// One chain step natively: `sponge(C ‖ items ‖ aux)`, exactly what the leaf constrains.
#[must_use]
pub fn chain_step(c: &Lanes, items: &[Lanes], aux: &Lanes) -> Option<Lanes> {
    if items.len() != CHUNK_TAGS {
        return None;
    }
    let words: Vec<Fa4> = c.iter().copied().chain(items.iter().flat_map(|t| t.iter().copied())).chain(aux.iter().copied()).collect();
    Some(sponge_words(&words))
}

/// The aux of an output-leaf chunk that is not a record's last.
#[must_use]
pub fn out_aux() -> Lanes {
    let mut a = [Fa4::ZERO; RATE];
    a[4] = Fa4::ONE;
    a
}

/// The aux of record `index`'s LAST chunk (an output chunk): the index's three 31-bit words, END, the output role, a
/// domain word. `index` is the chain's OWN record count, never a node's arrival ordinal nor a record address.
#[must_use]
pub fn end_aux(index: u64) -> Lanes {
    let w = |x: u64| Fa4::from_u32((x & 0x7FFF_FFFF) as u32);
    [w(index), w(index >> 31), w(index >> 62), Fa4::ONE, Fa4::ONE, Fa4::ZERO, Fa4::ZERO, Fa4::from_u32(0x454E_4431)]
}

/// A domain filler (proof-internal padding of a record's tags or outputs to whole chunks): a sponge image of a domain
/// word, the role and `i`. A real tag or leaf is the image of other functions, so the two never meet except by a collision.
#[must_use]
pub fn filler_tag(i: u64) -> Lanes {
    sponge_words(&[Fa4::from_u32(0x4142_5346), Fa4::from_u32(0x494C_4C31), Fa4::from_u32(i as u32 & 0x7FFF_FFFF), Fa4::from_u32((i >> 31) as u32 & 0x7FFF_FFFF)])
}

/// The digest of a list, in order: each entry's nullifier lanes, then its leaf lanes.
#[must_use]
pub fn nfs_digest(entries: &[Entry]) -> Lanes {
    let words: Vec<Fa4> = entries.iter().flat_map(|(n, l)| n.iter().chain(l.iter()).copied()).collect();
    sponge_words(&words)
}

pub(crate) fn bit(b: bool) -> Fa4 {
    if b {
        Fa4::ONE
    } else {
        Fa4::ZERO
    }
}

/// A carrier's statement digest: `sponge(list ‖ C_start ‖ C_end ‖ F_start ‖ F_end)`.
#[must_use]
pub fn abs_io(list_d: &Lanes, c_start: &Lanes, c_end: &Lanes, f_start: &[bool], f_end: &[bool]) -> Lanes {
    let words: Vec<Fa4> = list_d.iter().chain(c_start).chain(c_end).copied().chain(f_start.iter().map(|&b| bit(b))).chain(f_end.iter().map(|&b| bit(b))).collect();
    sponge_words(&words)
}

/// A carrier program's shape.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AbsKind {
    /// (entries, tag chunks, output chunks): one record
    Leaf(usize, usize, usize),
    /// (left, right)
    Merge(Box<AbsKind>, Box<AbsKind>),
    /// (child, entries appended): the child's statement restated over its list with `n` more entries, uncreated at both
    /// ends. Needs no proof beyond the child: an entry claimed uncreated is only ever checked LESS, and the spend wrapper
    /// refuses an entry whose bit never became 1, so a zero bit can never admit.
    Join(Box<AbsKind>, usize),
}

impl AbsKind {
    fn entries(&self) -> usize {
        match self {
            AbsKind::Leaf(k, _, _) => *k,
            AbsKind::Merge(l, _) => l.entries(),
            AbsKind::Join(c, n) => c.entries() + n,
        }
    }
}

/// The kinds a node of `k` carries claims about: every kind strictly below it, sorted.
#[must_use]
pub fn carried(k: &AbsKind) -> Vec<AbsKind> {
    let mut set = std::collections::BTreeSet::new();
    let kids: Vec<&AbsKind> = match k {
        AbsKind::Merge(l, r) => vec![l.as_ref(), r.as_ref()],
        AbsKind::Join(c, _) => vec![c.as_ref()],
        AbsKind::Leaf(..) => Vec::new(),
    };
    for c in kids {
        set.insert(c.clone());
        set.extend(carried(c));
    }
    set.into_iter().collect()
}

/// A claim about one program's preprocessed columns (limbs as canonical u32).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsClaim {
    pub kind: AbsKind,
    pub y: Vec<[u32; 4]>,
    pub v: Vec<[u32; 4]>,
}

/// A carrier: the SSA proof, its kind, its statement's parts, the claims it carries about every kind below it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbsProof {
    pub proof: Vec<u8>,
    pub nvars: usize,
    pub kind: AbsKind,
    pub nfs_d: [u32; RATE],
    pub c_start: [u32; RATE],
    pub c_end: [u32; RATE],
    pub f_start: Vec<bool>,
    pub f_end: Vec<bool>,
    pub claims: Vec<AbsClaim>,
}

pub(crate) fn lanes_u32(l: &Lanes) -> [u32; RATE] {
    l.map(|x| x.as_canonical_u32())
}
pub(crate) fn lanes_of_u32(v: &[u32; RATE]) -> Option<Lanes> {
    // Canonical only: a lane at or above the modulus is not a field element, and two encodings of one value would let one
    // statement travel under two names.
    let mut out = [Fa4::ZERO; RATE];
    for i in 0..RATE {
        let f = Fa4::from_u32(v[i]);
        if f.as_canonical_u32() != v[i] {
            return None;
        }
        out[i] = f;
    }
    Some(out)
}

fn program_cache() -> &'static std::sync::Mutex<std::collections::HashMap<AbsKind, std::sync::Arc<Program>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<AbsKind, std::sync::Arc<Program>>>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}
fn cached(k: &AbsKind) -> Option<std::sync::Arc<Program>> {
    program_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(k).cloned()
}
fn remember(k: &AbsKind, p: Program) -> std::sync::Arc<Program> {
    let a = std::sync::Arc::new(p);
    program_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(k.clone(), a.clone());
    a
}

pub(crate) fn base(a: Addr) -> Ext {
    Ext([a, ZERO, ZERO, ZERO])
}

/// The leaf's values (absent: the statement-only build every verifier makes, zeros throughout).
pub(crate) struct LeafVals<'a> {
    pub(crate) entries: &'a [Entry],
    pub(crate) c_start: Lanes,
    pub(crate) f_start: &'a [bool],
    /// ⭐ A-F114 — the records the leaf lays, in chain order: one for a single-record leaf, S for a SPAN leaf (every record
    /// of one shape), so one proof follows S records and a carrier keeps pace with the chain (the feasibility finding).
    pub(crate) recs: &'a [Record],
    /// A dishonest prover's created bits (tamper pins only; `None` on every honest path).
    pub(crate) force_created: Option<&'a [bool]>,
}

/// The created bits a record sets: an entry not yet created whose leaf is among the record's outputs.
pub(crate) fn created_here(entries: &[Entry], f_start: &[bool], recs: &[Record]) -> Vec<bool> {
    entries
        .iter()
        .zip(f_start)
        .map(|((_, leaf), &fs)| !fs && recs.iter().any(|rec| rec.outs.iter().any(|(items, _)| items.contains(leaf))))
        .collect()
}

/// A record leaf's program over `k` entries, `t` tag chunks and `o` output chunks; returns the builder and the statement.
#[allow(clippy::type_complexity)]
pub(crate) fn leaf_builder(k: usize, t: usize, o: usize, vals: Option<&LeafVals<'_>>) -> Result<(Builder, Lanes, Lanes, Lanes, Vec<bool>), String> {
    span_leaf_builder(k, t, o, 1, vals)
}

/// ⭐ A-F114 — THE SPAN LEAF: `s` records of one shape `(t, o)` laid in chain order, each chunk's role bound by its place in
/// its own record (a tag chunk's aux zero, a middle output chunk `out_aux`, a record's last chunk END). An entry created
/// anywhere in the span is absent from every tag of the span: sound, because a nullifier cannot appear before its note is
/// made (a note created and spent inside one span has no leaf for it, so a carrier ends a span at its own spend's record).
#[allow(clippy::type_complexity)]
pub(crate) fn span_leaf_builder(k: usize, t: usize, o: usize, s: usize, vals: Option<&LeafVals<'_>>) -> Result<(Builder, Lanes, Lanes, Lanes, Vec<bool>), String> {
    if k == 0 || t == 0 || o == 0 || s == 0 {
        return Err("a leaf states at least one entry over a record of at least one tag and one output chunk".into());
    }
    let mut b = Builder::new();
    let zero = [Fa4::ZERO; RATE];
    // natively first, so the statement is known before the public values are written
    let (list_v, cs_v, ce_v, fs_v, fe_v) = match vals {
        Some(v) => {
            if v.entries.len() != k || v.f_start.len() != k || v.recs.len() != s || v.recs.iter().any(|r| r.tags.len() != t || r.outs.len() != o) {
                return Err("the leaf's values are not its kind's".into());
            }
            let mut c = v.c_start;
            for rec in v.recs {
                for (items, aux) in rec.tags.iter().chain(&rec.outs) {
                    c = chain_step(&c, items, aux).ok_or("a chunk is not CHUNK_TAGS items")?;
                }
            }
            let cr = v.force_created.map_or_else(|| created_here(v.entries, v.f_start, v.recs), <[bool]>::to_vec);
            let fe: Vec<bool> = v.f_start.iter().zip(&cr).map(|(a, b)| *a || *b).collect();
            (nfs_digest(v.entries), v.c_start, c, v.f_start.to_vec(), fe)
        }
        None => (zero, zero, zero, vec![false; k], vec![false; k]),
    };
    let io_v = if vals.is_some() { abs_io(&list_v, &cs_v, &ce_v, &fs_v, &fe_v) } else { zero };
    let io = b.public_vals(&io_v);
    let kk = horner_k();
    let horner = |b: &mut Builder, lanes: &[Addr]| -> Ext {
        let mut s = base(lanes[RATE - 1]);
        for l in (0..RATE - 1).rev() {
            s = b.mul_k_add(s, kk, base(lanes[l]));
        }
        s
    };
    // the entries, their digest, their combinations
    let e_words: Vec<Fa4> = match vals {
        Some(v) => v.entries.iter().flat_map(|(n, l)| n.iter().chain(l.iter()).copied()).collect(),
        None => vec![Fa4::ZERO; k * 2 * RATE],
    };
    let ea = b.load(&e_words);
    let list_d = sponge_addrs(&mut b, &ea);
    let nprime: Vec<Ext> = (0..k).map(|j| horner(&mut b, &ea[j * 2 * RATE..j * 2 * RATE + RATE])).collect();
    // the bits: F_start boolean, created boolean and never on an already-created entry, F_end = F_start + created
    let created_v: Vec<bool> = match vals {
        Some(v) => v.force_created.map_or_else(|| created_here(v.entries, v.f_start, v.recs), <[bool]>::to_vec),
        None => vec![false; k],
    };
    let fsa = b.load(&fs_v.iter().map(|&x| bit(x)).collect::<Vec<_>>());
    let cra = b.load(&created_v.iter().map(|&x| bit(x)).collect::<Vec<_>>());
    let mut fe: Vec<Ext> = Vec::with_capacity(k);
    let mut neg_fe: Vec<Ext> = Vec::with_capacity(k);
    for j in 0..k {
        let (s, c) = (base(fsa[j]), base(cra[j]));
        for x in [s, c] {
            let nx = b.sub(Ext::ZERO, x);
            b.assert_mul_add_zero(x, x, nx); // x² − x = 0
        }
        b.assert_mul_add_zero(s, c, Ext::ZERO); // created only once
        let e = b.add(s, c);
        neg_fe.push(b.sub(Ext::ZERO, e));
        fe.push(e);
    }
    // the chain from C_start through the record: tags (checked), then outputs (scanned for the entries' leaves)
    let cs = b.load(&cs_v);
    let mut cur: Vec<Addr> = cs.clone();
    // EXACT equality for the created bit (never a fixed-point combination: a forged leaf could match one): per entry, a
    // boolean mark on each output item, Σ mark·(o_l − leaf_l) = 0 in every lane, and Σ mark = created
    let mut acc: Vec<[Ext; RATE]> = vec![[Ext::ZERO; RATE]; k];
    let mut marks: Vec<Ext> = vec![Ext::ZERO; k];
    let leaf_v: Vec<Lanes> = match vals {
        Some(v) => v.entries.iter().map(|(_, l)| *l).collect(),
        None => vec![zero; k],
    };
    let mut marked: Vec<bool> = vec![false; k];
    for (r, ci) in (0..s).flat_map(|r| (0..t + o).map(move |ci| (r, ci))) {
        let is_tag = ci < t;
        let last = ci + 1 == t + o;
        let (iw, aw): (Vec<Fa4>, Vec<Fa4>) = match vals {
            Some(v) => {
                let ch = if is_tag { &v.recs[r].tags[ci] } else { &v.recs[r].outs[ci - t] };
                (ch.0.iter().flat_map(|x| x.iter().copied()).collect(), ch.1.to_vec())
            }
            None => (vec![Fa4::ZERO; CHUNK_TAGS * RATE], vec![Fa4::ZERO; RATE]),
        };
        let ia = b.load(&iw);
        let xa = b.load(&aw);
        // THE ROLE, BOUND: the aux the chain absorbs says what this chunk is, so a tag chunk cannot be passed as outputs
        if is_tag {
            for l in 0..RATE {
                b.assert_eq(base(xa[l]), Ext::ZERO);
            }
        } else if last {
            b.assert_eq(base(xa[3]), Ext::ONE); // END
            b.assert_eq(base(xa[4]), Ext::ONE); // output role
            b.assert_eq(base(xa[5]), Ext::ZERO);
            b.assert_eq(base(xa[6]), Ext::ZERO);
        } else {
            let want = out_aux();
            for l in 0..RATE {
                let w = if want[l] == Fa4::ONE { Ext::ONE } else { Ext::ZERO };
                b.assert_eq(base(xa[l]), w);
            }
        }
        for it in 0..CHUNK_TAGS {
            let p = if is_tag { horner(&mut b, &ia[it * RATE..(it + 1) * RATE]) } else { Ext::ZERO };
            if is_tag {
                for j in 0..k {
                    let d = b.sub(p, nprime[j]);
                    let dv = b.ext_val(d);
                    let active = b.ext_val(fe[j]) != Ea4::ZERO;
                    // active: d·w = 1, so a tag equal to the nullifier has no w and the prover's value check refuses it
                    let w = b.load_ext(if active { dv.try_inverse().unwrap_or(Ea4::ZERO) } else { Ea4::ZERO });
                    b.assert_mul_add_zero(d, w, neg_fe[j]);
                }
            } else {
                let _ = p;
                let item_v: Lanes = core::array::from_fn(|l| b.val(ia[it * RATE + l]));
                for j in 0..k {
                    // the prover marks the FIRST output equal to the leaf, and only for an entry created here
                    let m = created_v[j] && !marked[j] && item_v == leaf_v[j];
                    if m {
                        marked[j] = true;
                    }
                    let mk = b.load_ext(Ea4::from(bit(m)));
                    let nmk = b.sub(Ext::ZERO, mk);
                    b.assert_mul_add_zero(mk, mk, nmk); // boolean
                    for l in 0..RATE {
                        let d = b.sub(base(ia[it * RATE + l]), base(ea[j * 2 * RATE + RATE + l]));
                        acc[j][l] = b.mul_add(mk, d, acc[j][l]);
                    }
                    marks[j] = b.add(marks[j], mk);
                }
            }
        }
        let words: Vec<Addr> = cur.iter().copied().chain(ia.iter().copied()).chain(xa.iter().copied()).collect();
        cur = sponge_addrs(&mut b, &words).to_vec();
    }
    // a created bit holds exactly where one output IS the entry's leaf, lane for lane
    for j in 0..k {
        for l in 0..RATE {
            b.assert_eq(acc[j][l], Ext::ZERO);
        }
        b.assert_eq(marks[j], base(cra[j]));
    }
    // io = sponge(list ‖ C_start ‖ C_end ‖ F_start ‖ F_end)
    let words: Vec<Addr> =
        list_d.iter().copied().chain(cs.iter().copied()).chain(cur.iter().copied()).chain(fsa.iter().copied()).chain(fe.iter().map(|e| e.0[0])).collect();
    let d = sponge_addrs(&mut b, &words);
    for l in 0..RATE {
        b.assert_eq(base(d[l]), base(io[l]));
    }
    Ok((b, list_v, cs_v, ce_v, fe_v))
}

fn leaf_program(k: usize, t: usize, o: usize) -> Result<std::sync::Arc<Program>, String> {
    let kind = AbsKind::Leaf(k, t, o);
    if let Some(p) = cached(&kind) {
        return Ok(p);
    }
    let (b, ..) = leaf_builder(k, t, o, None)?;
    let (_, prog) = lay(&b)?;
    Ok(remember(&kind, prog))
}

/// Prove one record for a list: from `c_start` with created bits `f_start`, every entry created by the end of the record
/// is absent from its tags. `None` if a created entry's nullifier is a tag here, or the record's chunks are malformed.
#[must_use]
pub fn prove_leaf(entries: &[Entry], c_start: Lanes, f_start: &[bool], rec: &Record) -> Option<Vec<u8>> {
    prove_leaf_with(entries, c_start, f_start, rec, None)
}

fn prove_leaf_with(entries: &[Entry], c_start: Lanes, f_start: &[bool], rec: &Record, force_created: Option<&[bool]>) -> Option<Vec<u8>> {
    let v = LeafVals { entries, c_start, f_start, recs: std::slice::from_ref(rec), force_created };
    let (k, t, o) = (entries.len(), rec.tags.len(), rec.outs.len());
    let (b, list_d, cs, ce, fe) = leaf_builder(k, t, o, Some(&v)).ok()?;
    if b.mismatch.is_some() {
        return None; // a spent created entry, or a chunk whose role is not its place: no witness, no proof
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    leaf_program(k, t, o).ok()?;
    postcard::to_allocvec(&AbsProof {
        proof,
        nvars: prog.nvars,
        kind: AbsKind::Leaf(k, t, o),
        nfs_d: lanes_u32(&list_d),
        c_start: lanes_u32(&cs),
        c_end: lanes_u32(&ce),
        f_start: f_start.to_vec(),
        f_end: fe,
        claims: Vec::new(),
    })
    .ok()
}

/// A child as its merge sees it.
struct Kid<'a> {
    kind: AbsKind,
    prog: std::sync::Arc<Program>,
    claims: Vec<AbsClaim>,
    proof: Option<&'a [u8]>,
}

pub(crate) fn claim_lanes(c: &AbsClaim) -> Vec<Fa4> {
    c.y.iter().chain(&c.v).flat_map(|l| l.iter().map(|&x| Fa4::from_u32(x))).collect()
}
pub(crate) fn claims_digest(cs: &[AbsClaim]) -> Lanes {
    sponge_words(&cs.iter().flat_map(claim_lanes).collect::<Vec<_>>())
}

/// The meeting parts of a merge: (list, left start, meeting value, right end, left bits, meeting bits, right bits).
type Ends = (Lanes, Lanes, Lanes, Lanes, Vec<bool>, Vec<bool>, Vec<bool>);

/// A merge's program: the shared parts loaded once, each child's statement hashed from them in circuit and its proof
/// verified in circuit, each kind's claims folded into one.
fn merge_builder(kids: [&Kid<'_>; 2], k: usize, ends: Option<&Ends>) -> Result<(Builder, Vec<AbsClaim>), String> {
    let gate = ssa_gate_program().ok_or("the universal gate does not trace")?;
    let mut b = Builder::new();
    let with_values = ends.is_some();
    let z = |v: Fa4| if with_values { v } else { Fa4::ZERO };
    let zero = [Fa4::ZERO; RATE];
    let none = vec![false; k];
    let (nd, a_s, mid, b_e, fa, fm, fb) = match ends {
        Some(e) => e.clone(),
        None => (zero, zero, zero, zero, none.clone(), none.clone(), none),
    };
    let lb = |v: &[bool]| v.iter().map(|&x| bit(x)).collect::<Vec<_>>();
    let nda = b.load(&nd);
    let asa = b.load(&a_s);
    let mida = b.load(&mid);
    let bea = b.load(&b_e);
    let faa = b.load(&lb(&fa));
    let fma = b.load(&lb(&fm));
    let fba = b.load(&lb(&fb));
    let mut groups: std::collections::BTreeMap<AbsKind, Vec<Claim>> = std::collections::BTreeMap::new();
    for (i, kid) in kids.iter().enumerate() {
        let (s, e, f0, f1) = if i == 0 { (&asa, &mida, &faa, &fma) } else { (&mida, &bea, &fma, &fba) };
        let words: Vec<Addr> = nda.iter().chain(s.iter()).chain(e.iter()).chain(f0.iter()).chain(f1.iter()).copied().collect();
        let mut stmt = sponge_addrs(&mut b, &words).to_vec();
        if !matches!(kid.kind, AbsKind::Leaf(..)) {
            let lanes: Vec<Fa4> = kid.claims.iter().flat_map(claim_lanes).map(z).collect();
            let la = b.load(&lanes);
            let cd = sponge_addrs(&mut b, &la);
            stmt.extend_from_slice(&cd);
            let want = carried(&kid.kind);
            if want.len() != kid.claims.len() {
                return Err("a child carries another number of claims than its kind".into());
            }
            let mut off = 0usize;
            for (ck, c) in want.iter().zip(&kid.claims) {
                if &c.kind != ck {
                    return Err("a child's claims are not its kind's".into());
                }
                let n = c.y.len();
                let ext = |i: usize| Ext([la[off + 4 * i], la[off + 4 * i + 1], la[off + 4 * i + 2], la[off + 4 * i + 3]]);
                let point: Vec<Ext> = (0..n).map(ext).collect();
                let vals: Vec<Ext> = (n..n + crate::ssa::NFIXED).map(ext).collect();
                off += 4 * (n + crate::ssa::NFIXED);
                groups.entry(ck.clone()).or_default().push(Claim { point, cols: Cols::All, vals });
            }
        }
        let shape = ChildShape::of(&kid.prog, &stmt).ok_or("a child's statement is not its program's")?;
        let d = emit_ssa_child(&mut b, &shape, &gate, kid.proof, &mut WhirOnSsa)?;
        let g = groups.entry(kid.kind.clone()).or_default();
        g.push(Claim { point: d.x.clone(), cols: Cols::Bus, vals: d.fx.clone() });
        g.push(Claim { point: d.r.clone(), cols: Cols::All, vals: d.fr.clone() });
    }
    let mut out = Vec::new();
    let mut out_lanes: Vec<Addr> = Vec::new();
    for (kind, claims) in &groups {
        let prog = cached(kind).ok_or("a child kind's program is not built")?;
        let f = emit_fold(&mut b, claims, prog.nvars, with_values.then_some(&prog.fixed[..]))?;
        let ev = |e: &Ext| u4(b.ext_val(*e));
        out.push(AbsClaim { kind: kind.clone(), y: f.y.iter().map(ev).collect(), v: f.v.iter().map(ev).collect() });
        for e in f.y.iter().chain(&f.v) {
            out_lanes.extend_from_slice(&e.0);
        }
    }
    // the statement: io = sponge(list ‖ a_s ‖ b_e ‖ F_a ‖ F_b), then the digest of the carried claims
    let words: Vec<Addr> = nda.iter().chain(asa.iter()).chain(bea.iter()).chain(faa.iter()).chain(fba.iter()).copied().collect();
    let io_d = sponge_addrs(&mut b, &words);
    let cd_d = sponge_addrs(&mut b, &out_lanes);
    let vals: Vec<Fa4> = io_d.iter().chain(&cd_d).map(|&a| if with_values { b.val(a) } else { Fa4::ZERO }).collect();
    let st = b.public_vals(&vals);
    for l in 0..2 * RATE {
        let d = if l < RATE { io_d[l] } else { cd_d[l - RATE] };
        b.assert_eq(base(d), base(st[l]));
    }
    Ok((b, out))
}

fn program_of(k: &AbsKind) -> Result<std::sync::Arc<Program>, String> {
    if let Some(p) = cached(k) {
        return Ok(p);
    }
    match k {
        AbsKind::Leaf(n, t, o) => leaf_program(*n, *t, *o),
        AbsKind::Join(c, n) => {
            let prog = program_of(c)?;
            let claims = blank_claims(c);
            let kid = Kid { kind: (**c).clone(), prog, claims, proof: None };
            let (b, _) = join_builder(&kid, *n, None)?;
            let (_, p) = lay(&b)?;
            Ok(remember(k, p))
        }
        AbsKind::Merge(l, r) => {
            let kid = |c: &AbsKind| -> Result<Kid<'static>, String> {
                let prog = program_of(c)?;
                let claims = carried(c)
                    .into_iter()
                    .map(|kk| {
                        let n = cached(&kk).map_or(0, |p| p.nvars);
                        AbsClaim { kind: kk, y: vec![[0; 4]; n], v: vec![[0; 4]; crate::ssa::NFIXED] }
                    })
                    .collect();
                Ok(Kid { kind: c.clone(), prog, claims, proof: None })
            };
            let (kl, kr) = (kid(l)?, kid(r)?);
            let (b, _) = merge_builder([&kl, &kr], l.entries(), None)?;
            let (_, prog) = lay(&b)?;
            Ok(remember(k, prog))
        }
    }
}

/// Zero-shaped claims of every kind below `c` (a statement-only build's stand-ins).
fn blank_claims(c: &AbsKind) -> Vec<AbsClaim> {
    carried(c)
        .into_iter()
        .map(|kk| {
            let n = cached(&kk).map_or(0, |p| p.nvars);
            AbsClaim { kind: kk, y: vec![[0; 4]; n], v: vec![[0; 4]; crate::ssa::NFIXED] }
        })
        .collect()
}

/// A join's program: the child's list and statement loaded, the child verified in circuit, the statement restated over
/// the list with `n` appended entries whose bits are the constant zero at both ends.
fn join_builder(child: &Kid<'_>, n: usize, vals: Option<(&AbsProof, &[Entry], &[Entry])>) -> Result<(Builder, Vec<AbsClaim>), String> {
    let gate = ssa_gate_program().ok_or("the universal gate does not trace")?;
    let k = child.kind.entries();
    let mut b = Builder::new();
    let with_values = vals.is_some();
    let z = |v: Fa4| if with_values { v } else { Fa4::ZERO };
    let zero = [Fa4::ZERO; RATE];
    let words_of = |es: &[Entry]| -> Vec<Fa4> { es.iter().flat_map(|(nf, l)| nf.iter().chain(l.iter()).copied()).collect() };
    let (old_w, add_w, cs_v, ce_v, fs_v, fe_v) = match vals {
        Some((ap, old, add)) => {
            if old.len() != k || add.len() != n || ap.nfs_d != lanes_u32(&nfs_digest(old)) {
                return Err("the join's values are not its kind's".into());
            }
            (
                words_of(old),
                words_of(add),
                lanes_of_u32(&ap.c_start).ok_or("non-canonical")?,
                lanes_of_u32(&ap.c_end).ok_or("non-canonical")?,
                ap.f_start.iter().map(|&x| bit(x)).collect::<Vec<_>>(),
                ap.f_end.iter().map(|&x| bit(x)).collect::<Vec<_>>(),
            )
        }
        None => (vec![Fa4::ZERO; k * 2 * RATE], vec![Fa4::ZERO; n * 2 * RATE], zero, zero, vec![Fa4::ZERO; k], vec![Fa4::ZERO; k]),
    };
    let oa = b.load(&old_w);
    let aa = b.load(&add_w);
    let old_d = sponge_addrs(&mut b, &oa);
    let all: Vec<Addr> = oa.iter().chain(aa.iter()).copied().collect();
    let new_d = sponge_addrs(&mut b, &all);
    let csa = b.load(&cs_v);
    let cea = b.load(&ce_v);
    let fsa = b.load(&fs_v);
    let fea = b.load(&fe_v);
    // the child, under its own statement
    let words: Vec<Addr> = old_d.iter().chain(csa.iter()).chain(cea.iter()).chain(fsa.iter()).chain(fea.iter()).copied().collect();
    let mut stmt = sponge_addrs(&mut b, &words).to_vec();
    let mut groups: std::collections::BTreeMap<AbsKind, Vec<Claim>> = std::collections::BTreeMap::new();
    if !matches!(child.kind, AbsKind::Leaf(..)) {
        let lanes: Vec<Fa4> = child.claims.iter().flat_map(claim_lanes).map(z).collect();
        let la = b.load(&lanes);
        let cd = sponge_addrs(&mut b, &la);
        stmt.extend_from_slice(&cd);
        let want = carried(&child.kind);
        if want.len() != child.claims.len() {
            return Err("the child carries another number of claims than its kind".into());
        }
        let mut off = 0usize;
        for (ck, c) in want.iter().zip(&child.claims) {
            if &c.kind != ck {
                return Err("the child's claims are not its kind's".into());
            }
            let m = c.y.len();
            let ext = |i: usize| Ext([la[off + 4 * i], la[off + 4 * i + 1], la[off + 4 * i + 2], la[off + 4 * i + 3]]);
            let point: Vec<Ext> = (0..m).map(ext).collect();
            let vv: Vec<Ext> = (m..m + crate::ssa::NFIXED).map(ext).collect();
            off += 4 * (m + crate::ssa::NFIXED);
            groups.entry(ck.clone()).or_default().push(Claim { point, cols: Cols::All, vals: vv });
        }
    }
    let shape = ChildShape::of(&child.prog, &stmt).ok_or("the child's statement is not its program's")?;
    let d = emit_ssa_child(&mut b, &shape, &gate, child.proof, &mut WhirOnSsa)?;
    let g = groups.entry(child.kind.clone()).or_default();
    g.push(Claim { point: d.x.clone(), cols: Cols::Bus, vals: d.fx.clone() });
    g.push(Claim { point: d.r.clone(), cols: Cols::All, vals: d.fr.clone() });
    let mut out = Vec::new();
    let mut out_lanes: Vec<Addr> = Vec::new();
    for (kind, claims) in &groups {
        let prog = cached(kind).ok_or("a child kind's program is not built")?;
        let f = emit_fold(&mut b, claims, prog.nvars, with_values.then_some(&prog.fixed[..]))?;
        let ev = |e: &Ext| u4(b.ext_val(*e));
        out.push(AbsClaim { kind: kind.clone(), y: f.y.iter().map(ev).collect(), v: f.v.iter().map(ev).collect() });
        for e in f.y.iter().chain(&f.v) {
            out_lanes.extend_from_slice(&e.0);
        }
    }
    // the restated statement: the new list, the same span, the old bits then n constant zeros at each end
    let zeros = vec![ZERO; n];
    let words: Vec<Addr> = new_d
        .iter()
        .chain(csa.iter())
        .chain(cea.iter())
        .chain(fsa.iter())
        .chain(zeros.iter())
        .chain(fea.iter())
        .chain(zeros.iter())
        .copied()
        .collect();
    let io_d = sponge_addrs(&mut b, &words);
    let cd_d = sponge_addrs(&mut b, &out_lanes);
    let pv: Vec<Fa4> = io_d.iter().chain(&cd_d).map(|&a| if with_values { b.val(a) } else { Fa4::ZERO }).collect();
    let st = b.public_vals(&pv);
    for l in 0..2 * RATE {
        let dd = if l < RATE { io_d[l] } else { cd_d[l - RATE] };
        b.assert_eq(base(dd), base(st[l]));
    }
    Ok((b, out))
}

/// Restate a carrier over its list `old` with the entries `add` appended, uncreated at both ends (a wallet's new notes join
/// its one list before the record that makes them). `None` if `old` is not the carrier's list or the child does not verify.
#[must_use]
pub fn prove_join(child: &[u8], old: &[Entry], add: &[Entry]) -> Option<Vec<u8>> {
    let ap: AbsProof = postcard::from_bytes(child).ok()?;
    if add.is_empty() {
        return None;
    }
    let kid = Kid { kind: ap.kind.clone(), prog: program_of(&ap.kind).ok()?, claims: ap.claims.clone(), proof: Some(&ap.proof[..]) };
    let kind = AbsKind::Join(Box::new(ap.kind.clone()), add.len());
    program_of(&kind).ok()?;
    let (b, claims) = join_builder(&kid, add.len(), Some((&ap, old, add))).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    let all: Vec<Entry> = old.iter().chain(add).copied().collect();
    let mut fs = ap.f_start.clone();
    fs.extend(core::iter::repeat_n(false, add.len()));
    let mut fe = ap.f_end.clone();
    fe.extend(core::iter::repeat_n(false, add.len()));
    postcard::to_allocvec(&AbsProof { proof, nvars: prog.nvars, kind, nfs_d: lanes_u32(&nfs_digest(&all)), c_start: ap.c_start, c_end: ap.c_end, f_start: fs, f_end: fe, claims }).ok()
}

/// Merge two carriers over one list whose spans meet (`left.c_end == right.c_start`, `left.f_end == right.f_start`).
/// `None` if they do not meet, state other lists, or either child fails its own door in circuit.
#[must_use]
pub fn prove_merge(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    let l: AbsProof = postcard::from_bytes(left).ok()?;
    let r: AbsProof = postcard::from_bytes(right).ok()?;
    let k = l.kind.entries();
    if l.nfs_d != r.nfs_d || l.c_end != r.c_start || l.f_end != r.f_start || k != r.kind.entries() || l.f_start.len() != k || r.f_end.len() != k {
        return None; // a gap, two lists, or a flipped bit: no statement covers it
    }
    let ends: Ends = (lanes_of_u32(&l.nfs_d)?, lanes_of_u32(&l.c_start)?, lanes_of_u32(&l.c_end)?, lanes_of_u32(&r.c_end)?, l.f_start.clone(), l.f_end.clone(), r.f_end.clone());
    let kl = Kid { kind: l.kind.clone(), prog: program_of(&l.kind).ok()?, claims: l.claims.clone(), proof: Some(&l.proof[..]) };
    let kr = Kid { kind: r.kind.clone(), prog: program_of(&r.kind).ok()?, claims: r.claims.clone(), proof: Some(&r.proof[..]) };
    let kind = AbsKind::Merge(Box::new(l.kind.clone()), Box::new(r.kind.clone()));
    program_of(&kind).ok()?;
    let (b, claims) = merge_builder([&kl, &kr], k, Some(&ends)).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    postcard::to_allocvec(&AbsProof { proof, nvars: prog.nvars, kind, nfs_d: l.nfs_d, c_start: l.c_start, c_end: r.c_end, f_start: l.f_start, f_end: r.f_end, claims }).ok()
}

/// ⭐ THE DOOR: does `bytes` prove, for the list digesting to `list_d`, that from `c_start` (created bits `f_start`) to
/// `c_end` (bits `f_end`) every entry is absent from every record's tags from the record its note was made in? Native:
/// the statement digest, each carried claim against its kind's program, the SSA door under the statement. Fail-closed.
#[must_use]
pub fn verify(bytes: &[u8], list_d: &Lanes, c_start: &Lanes, f_start: &[bool], c_end: &Lanes, f_end: &[bool]) -> bool {
    if bytes.is_empty() || bytes.len() > ABS_MAX_BYTES {
        return false;
    }
    let Ok(ap) = postcard::from_bytes::<AbsProof>(bytes) else { return false };
    let k = ap.kind.entries();
    if f_start.len() != k || f_end.len() != k {
        return false;
    }
    if ap.nfs_d != lanes_u32(list_d) || ap.c_start != lanes_u32(c_start) || ap.c_end != lanes_u32(c_end) || ap.f_start != f_start || ap.f_end != f_end {
        return false;
    }
    let Ok(prog) = program_of(&ap.kind) else { return false };
    let want = carried(&ap.kind);
    if ap.claims.len() != want.len() {
        return false;
    }
    for (c, kk) in ap.claims.iter().zip(&want) {
        let Ok(p) = program_of(kk) else { return false };
        if &c.kind != kk || c.y.len() != p.nvars || c.v.len() != crate::ssa::NFIXED {
            return false;
        }
        let y: Vec<Ea4> = c.y.iter().map(e4).collect();
        let v: Vec<Ea4> = c.v.iter().map(e4).collect();
        if p.fixed_at(&y) != v {
            return false; // a folded claim the program does not satisfy
        }
    }
    let mut svals: Vec<Fa4> = abs_io(list_d, c_start, c_end, f_start, f_end).to_vec();
    if !matches!(ap.kind, AbsKind::Leaf(..)) {
        svals.extend_from_slice(&claims_digest(&ap.claims));
    }
    if svals.len() != prog.statement.len() || ap.nvars != prog.nvars {
        return false;
    }
    crate::ssa_door::verify(&ap.proof, &stated(&prog, &svals))
}

// ============================================================================================================================
// ⭐ THE SPEND WRAPPER (A-F114 phase 3 step 2): the one proof a spend carries, exposing ONLY the spent nullifier and the chain
// end. It verifies a list carrier IN CIRCUIT, selects the spent entry by a hidden one-hot mark, requires that entry's
// created bit at the carrier's end (its note was made in a real record of the span, every later record checked), and binds
// the entry's leaf to the spend's own member tuple: `P(P(leaf, binder), blind) = leaf_commit` (the production Poseidon2,
// `prod_perm_ssa`; DB-363's hiding commitment). The list, the carrier's start, the record and the position stay hidden.
// §9.6: (2) by the SSA door, the carrier and both hashes in circuit; (3) none created; (4) the node checks the end against
// its window and the records after it; (5) one SSA verify; (7) a constant; (8) (a).
// ============================================================================================================================

/// The wrapper's statement digest: `sponge(nf tag lanes ‖ binder ‖ leaf_commit ‖ C_end)`.
#[must_use]
pub fn spend_io(nf: &Lanes, binder: &Lanes, leaf_commit: &Lanes, c_end: &Lanes) -> Lanes {
    let words: Vec<Fa4> = nf.iter().chain(binder).chain(leaf_commit).chain(c_end).copied().collect();
    sponge_words(&words)
}

/// A spend wrapper: the SSA proof, its child carrier's kind, the claims it carries (about the child's kind and below).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendProof {
    pub proof: Vec<u8>,
    pub nvars: usize,
    pub child: AbsKind,
    pub claims: Vec<AbsClaim>,
}

/// What the prover holds for a wrapper (absent: the statement-only build).
struct WrapVals<'a> {
    entries: &'a [Entry],
    j: usize,
    carrier: &'a AbsProof,
    binder: Lanes,
    blind: Lanes,
}

fn wrap_cache() -> &'static std::sync::Mutex<std::collections::HashMap<AbsKind, std::sync::Arc<Program>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<AbsKind, std::sync::Arc<Program>>>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn wrap_builder(child: &Kid<'_>, vals: Option<&WrapVals<'_>>) -> Result<(Builder, Vec<AbsClaim>), String> {
    let gate = ssa_gate_program().ok_or("the universal gate does not trace")?;
    let k = child.kind.entries();
    let mut b = Builder::new();
    let with_values = vals.is_some();
    let z = |v: Fa4| if with_values { v } else { Fa4::ZERO };
    let zero = [Fa4::ZERO; RATE];
    // the statement, natively
    let (nf_v, leaf_v, lc_v, ce_v) = match vals {
        Some(v) => {
            let (nf, leaf) = *v.entries.get(v.j).ok_or("the spent entry is not in the list")?;
            let inner = usdm_decider::poseidon2_compress::compress(&lanes_digest(&leaf), &lanes_digest(&v.binder));
            let lc = usdm_decider::poseidon2_compress::compress(&inner, &lanes_digest(&v.blind));
            (nf, leaf, digest_lanes(&lc), lanes_of_u32(&v.carrier.c_end).ok_or("a non-canonical end")?)
        }
        None => (zero, zero, zero, zero),
    };
    let binder_v = vals.map_or(zero, |v| v.binder);
    let io_v = if with_values { spend_io(&nf_v, &binder_v, &lc_v, &ce_v) } else { zero };
    let io = b.public_vals(&io_v);
    // the public parts, loaded and hashed to io
    let nfa = b.load(&nf_v);
    let bda = b.load(&binder_v);
    let lca = b.load(&lc_v);
    let cea = b.load(&ce_v);
    // the list, the carrier's start and bits (hidden)
    let e_words: Vec<Fa4> = match vals {
        Some(v) => v.entries.iter().flat_map(|(n, l)| n.iter().chain(l.iter()).copied()).collect(),
        None => vec![Fa4::ZERO; k * 2 * RATE],
    };
    let ea = b.load(&e_words);
    let list_d = sponge_addrs(&mut b, &ea);
    let cs_v = match vals {
        Some(v) => lanes_of_u32(&v.carrier.c_start).ok_or("a non-canonical start")?,
        None => zero,
    };
    let csa = b.load(&cs_v);
    let fs_v: Vec<Fa4> = vals.map_or(vec![Fa4::ZERO; k], |v| v.carrier.f_start.iter().map(|&x| bit(x)).collect());
    let fe_v: Vec<Fa4> = vals.map_or(vec![Fa4::ZERO; k], |v| v.carrier.f_end.iter().map(|&x| bit(x)).collect());
    let fsa = b.load(&fs_v);
    let fea = b.load(&fe_v);
    // the hidden selection: one mark, on an entry whose nullifier is nf, whose leaf is `leaf`, and whose bit is set
    let la = b.load(&leaf_v);
    let mut msum = Ext::ZERO;
    let mut acc_nf = [Ext::ZERO; RATE];
    let mut acc_leaf = [Ext::ZERO; RATE];
    let mut acc_bit = Ext::ZERO;
    for i in 0..k {
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
    b.assert_eq(msum, Ext::ONE);
    for l in 0..RATE {
        b.assert_eq(acc_nf[l], Ext::ZERO);
        b.assert_eq(acc_leaf[l], Ext::ZERO);
    }
    b.assert_eq(acc_bit, Ext::ZERO);
    // the leaf bound to the spend's member tuple: P(P(leaf, binder), blind) = leaf_commit
    let blind_v = vals.map_or(zero, |v| v.blind);
    let bla = b.load(&blind_v);
    let e8 = |a: &[Addr]| -> [Ext; 8] { core::array::from_fn(|i| base(a[i])) };
    let inner = crate::prod_perm_ssa::production_compress(&mut b, e8(&la), e8(&bda));
    let lc = crate::prod_perm_ssa::production_compress(&mut b, inner, e8(&bla));
    for l in 0..RATE {
        b.assert_eq(lc[l], base(lca[l]));
    }
    // the carrier, verified in circuit under the statement built from these very addresses
    let words: Vec<Addr> = list_d.iter().chain(csa.iter()).chain(cea.iter()).chain(fsa.iter()).chain(fea.iter()).copied().collect();
    let mut stmt = sponge_addrs(&mut b, &words).to_vec();
    let mut groups: std::collections::BTreeMap<AbsKind, Vec<Claim>> = std::collections::BTreeMap::new();
    if !matches!(child.kind, AbsKind::Leaf(..)) {
        let lanes: Vec<Fa4> = child.claims.iter().flat_map(claim_lanes).map(z).collect();
        let cl = b.load(&lanes);
        let cd = sponge_addrs(&mut b, &cl);
        stmt.extend_from_slice(&cd);
        let want = carried(&child.kind);
        if want.len() != child.claims.len() {
            return Err("the carrier carries another number of claims than its kind".into());
        }
        let mut off = 0usize;
        for (ck, c) in want.iter().zip(&child.claims) {
            if &c.kind != ck {
                return Err("the carrier's claims are not its kind's".into());
            }
            let n = c.y.len();
            let ext = |i: usize| Ext([cl[off + 4 * i], cl[off + 4 * i + 1], cl[off + 4 * i + 2], cl[off + 4 * i + 3]]);
            let point: Vec<Ext> = (0..n).map(ext).collect();
            let vv: Vec<Ext> = (n..n + crate::ssa::NFIXED).map(ext).collect();
            off += 4 * (n + crate::ssa::NFIXED);
            groups.entry(ck.clone()).or_default().push(Claim { point, cols: Cols::All, vals: vv });
        }
    }
    let shape = ChildShape::of(&child.prog, &stmt).ok_or("the carrier's statement is not its program's")?;
    let d = emit_ssa_child(&mut b, &shape, &gate, child.proof, &mut WhirOnSsa)?;
    let g = groups.entry(child.kind.clone()).or_default();
    g.push(Claim { point: d.x.clone(), cols: Cols::Bus, vals: d.fx.clone() });
    g.push(Claim { point: d.r.clone(), cols: Cols::All, vals: d.fr.clone() });
    let mut out = Vec::new();
    let mut out_lanes: Vec<Addr> = Vec::new();
    for (kind, claims) in &groups {
        let prog = cached(kind).ok_or("a child kind's program is not built")?;
        let f = emit_fold(&mut b, claims, prog.nvars, with_values.then_some(&prog.fixed[..]))?;
        let ev = |e: &Ext| u4(b.ext_val(*e));
        out.push(AbsClaim { kind: kind.clone(), y: f.y.iter().map(ev).collect(), v: f.v.iter().map(ev).collect() });
        for e in f.y.iter().chain(&f.v) {
            out_lanes.extend_from_slice(&e.0);
        }
    }
    // io = sponge(nf ‖ binder ‖ leaf_commit ‖ C_end), then the claims' digest, both public
    let words: Vec<Addr> = nfa.iter().chain(bda.iter()).chain(lca.iter()).chain(cea.iter()).copied().collect();
    let io_d = sponge_addrs(&mut b, &words);
    for l in 0..RATE {
        b.assert_eq(base(io_d[l]), base(io[l]));
    }
    let cd_d = sponge_addrs(&mut b, &out_lanes);
    let cvals: Vec<Fa4> = cd_d.iter().map(|&a| if with_values { b.val(a) } else { Fa4::ZERO }).collect();
    let cst = b.public_vals(&cvals);
    for l in 0..RATE {
        b.assert_eq(base(cd_d[l]), base(cst[l]));
    }
    Ok((b, out))
}

fn lanes_digest(l: &Lanes) -> usdm_decider::poseidon2_compress::Digest {
    core::array::from_fn(|i| u64::from(l[i].as_canonical_u32()))
}
fn digest_lanes(d: &usdm_decider::poseidon2_compress::Digest) -> Lanes {
    core::array::from_fn(|i| Fa4::from_u64(d[i]))
}

fn wrap_program(child: &AbsKind) -> Result<std::sync::Arc<Program>, String> {
    if let Some(p) = wrap_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(child).cloned() {
        return Ok(p);
    }
    let prog = program_of(child)?;
    let claims = carried(child)
        .into_iter()
        .map(|kk| {
            let n = cached(&kk).map_or(0, |p| p.nvars);
            AbsClaim { kind: kk, y: vec![[0; 4]; n], v: vec![[0; 4]; crate::ssa::NFIXED] }
        })
        .collect();
    let kid = Kid { kind: child.clone(), prog, claims, proof: None };
    let (b, _) = wrap_builder(&kid, None)?;
    let (_, p) = lay(&b)?;
    let a = std::sync::Arc::new(p);
    wrap_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(child.clone(), a.clone());
    Ok(a)
}

/// The leaf commitment the spend's member tuple states for `leaf` under `binder` and `blind` (DB-363), natively.
#[must_use]
pub fn leaf_commit(leaf: &Lanes, binder: &Lanes, blind: &Lanes) -> Lanes {
    let inner = usdm_decider::poseidon2_compress::compress(&lanes_digest(leaf), &lanes_digest(binder));
    digest_lanes(&usdm_decider::poseidon2_compress::compress(&inner, &lanes_digest(blind)))
}

/// Prove a spend of entry `j` of `entries` from a list carrier (`carrier`, an [`AbsProof`]) whose end bit for `j` is set.
/// `None` if the entry is not created at the carrier's end, or the carrier does not verify in circuit.
#[must_use]
pub fn prove_spend(entries: &[Entry], j: usize, carrier: &[u8], binder: Lanes, blind: Lanes) -> Option<Vec<u8>> {
    let ap: AbsProof = postcard::from_bytes(carrier).ok()?;
    if ap.nfs_d != lanes_u32(&nfs_digest(entries)) || !ap.f_end.get(j).copied().unwrap_or(false) {
        return None; // another list, or the note is not made in the carrier's span: nothing to spend
    }
    let kid = Kid { kind: ap.kind.clone(), prog: program_of(&ap.kind).ok()?, claims: ap.claims.clone(), proof: Some(&ap.proof[..]) };
    wrap_program(&ap.kind).ok()?;
    let v = WrapVals { entries, j, carrier: &ap, binder, blind };
    let (b, claims) = wrap_builder(&kid, Some(&v)).ok()?;
    if b.mismatch.is_some() {
        return None;
    }
    let (rows, prog) = lay(&b).ok()?;
    let cols = crate::ssa::execute(&b, &rows, &prog).ok()?;
    let proof = crate::ssa_door::prove(&prog, cols)?;
    postcard::to_allocvec(&SpendProof { proof, nvars: prog.nvars, child: ap.kind, claims }).ok()
}

/// ⭐ THE SPEND DOOR: does `bytes` prove that the note behind `leaf_commit` (under `binder`) was made in a record of this
/// chain and that its nullifier (tag lanes `nf`) is a tag of no record from its making to `c_end`? Native: the claims
/// against their kinds' programs, the SSA door under `(nf, binder, leaf_commit, c_end)`. Fail-closed.
#[must_use]
pub fn verify_spend(bytes: &[u8], nf: &Lanes, binder: &Lanes, leaf_commit: &Lanes, c_end: &Lanes) -> bool {
    if bytes.is_empty() || bytes.len() > ABS_MAX_BYTES {
        return false;
    }
    let Ok(sp) = postcard::from_bytes::<SpendProof>(bytes) else { return false };
    let Ok(prog) = wrap_program(&sp.child) else { return false };
    let mut want = carried(&sp.child);
    want.push(sp.child.clone());
    want.sort();
    want.dedup();
    if sp.claims.len() != want.len() {
        return false;
    }
    for (c, kk) in sp.claims.iter().zip(&want) {
        let Ok(p) = program_of(kk) else { return false };
        if &c.kind != kk || c.y.len() != p.nvars || c.v.len() != crate::ssa::NFIXED {
            return false;
        }
        let y: Vec<Ea4> = c.y.iter().map(e4).collect();
        let v: Vec<Ea4> = c.v.iter().map(e4).collect();
        if p.fixed_at(&y) != v {
            return false;
        }
    }
    let mut svals: Vec<Fa4> = spend_io(nf, binder, leaf_commit, c_end).to_vec();
    svals.extend_from_slice(&claims_digest(&sp.claims));
    if svals.len() != prog.statement.len() || sp.nvars != prog.nvars {
        return false;
    }
    crate::ssa_door::verify(&sp.proof, &stated(&prog, &svals))
}

/// The lanes of a value as the door's `Ea4` sees them (for callers building statements from base lanes).
#[must_use]
pub fn ext_lanes(e: Ea4) -> [Fa4; 4] {
    let s: &[Fa4] = BasedVectorSpace::<Fa4>::as_basis_coefficients_slice(&e);
    [s[0], s[1], s[2], s[3]]
}

// TWO-PARTY-REVIEWED: the carrier is a pure function of the chain's chunks and the list; the cross-party claim (a
// wallet's carrier verifies at another node that folded the same records) is pinned where the node folds records (2c).
#[cfg(test)]
mod tests {

    /// ⭐ A-F114 — MEASURE the span leaf: rows a leaf of `s` records of the canonical shape takes (8 tag chunks: 256 padded
    /// tags; 8 output chunks: the block's leaves) over a 16-slot list. The family fixes every program at 2^15 rows, so the
    /// largest `s` whose leaf fits is the span length S. Prints the table; asserts a longer span never takes fewer rows
    /// (the circuit is laid, not proven, so this is seconds).
    #[test]
    fn s1_span_leaf_rows_by_record_count() {
        let (k, t, o) = (16usize, 8usize, 8usize);
        let mut last = 0usize;
        for s in [1usize, 2, 4, 8, 16, 32] {
            let (b, ..) = span_leaf_builder(k, t, o, s, None).expect("the span leaf builds");
            let (_, prog) = crate::ssa::lay(&b).expect("the span leaf lays");
            eprintln!("[s1] span of {s:>2} record(s): 2^{} rows", prog.nvars);
            assert!(prog.nvars >= last, "a longer span never takes fewer rows");
            last = prog.nvars;
        }
    }

    /// ⭐ A-F114 — MEASURE where a leaf's rows go: one canonical record (8 tag + 8 output chunks) by list size k, and a span
    /// of records at k = 1. Splits the absence check (k × tags) from the per-record chain hashing. Laid, not proven.
    #[test]
    fn s2_leaf_rows_by_list_size_and_span_at_one_slot() {
        let (t, o) = (8usize, 8usize);
        for k in [1usize, 2, 4, 8, 16] {
            let (b, ..) = span_leaf_builder(k, t, o, 1, None).expect("the leaf builds");
            let (_, prog) = crate::ssa::lay(&b).expect("the leaf lays");
            eprintln!("[s2] one record, k = {k:>2}: 2^{} rows", prog.nvars);
        }
        for s in [1usize, 2, 4, 8, 16] {
            let (b, ..) = span_leaf_builder(1, t, o, s, None).expect("the span leaf builds");
            let (_, prog) = crate::ssa::lay(&b).expect("the span leaf lays");
            eprintln!("[s2] k = 1, span of {s:>2}: 2^{} rows", prog.nvars);
        }
    }
    use super::*;

    fn lanes(seed: u64) -> Lanes {
        core::array::from_fn(|i| Fa4::from_u32(((seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919 + 1)) % 2_130_706_433) as u32))
    }
    fn items(seed: u64) -> Vec<Lanes> {
        (0..CHUNK_TAGS as u64).map(|t| lanes(seed * 1000 + t + 1)).collect()
    }
    /// A one-tag-chunk, one-output-chunk record `i` (tags from `i`, outputs from `i + 500`).
    fn rec(i: u64) -> Record {
        Record { tags: vec![(items(i), [Fa4::ZERO; RATE])], outs: vec![(items(i + 500), end_aux(i))] }
    }
    fn step_rec(c: &Lanes, r: &Record) -> Lanes {
        let mut c = *c;
        for (it, aux) in r.tags.iter().chain(&r.outs) {
            c = chain_step(&c, it, aux).unwrap();
        }
        c
    }

    /// ⭐ A1: a created entry absent from a record's tags proves, and the door accepts it at its own statement and refuses a
    /// moved start, a moved end, another list, a flipped end bit and a flipped byte (the lying prover: false in one place).
    #[test]
    fn a1_a_leaf_proves_absence_and_the_door_refuses_a_moved_statement() {
        let e = vec![(lanes(7), lanes(70))];
        let (c0, r) = (lanes(1), rec(1));
        let p = prove_leaf(&e, c0, &[true], &r).expect("an absent created entry proves");
        let c1 = step_rec(&c0, &r);
        let nd = nfs_digest(&e);
        assert!(verify(&p, &nd, &c0, &[true], &c1, &[true]), "the door accepts its own statement");
        assert!(!verify(&p, &nd, &lanes(2), &[true], &c1, &[true]), "LYING PROVER: a moved start is refused");
        assert!(!verify(&p, &nd, &c0, &[true], &lanes(3), &[true]), "LYING PROVER: a moved end is refused");
        assert!(!verify(&p, &nfs_digest(&[(lanes(8), lanes(70))]), &c0, &[true], &c1, &[true]), "LYING PROVER: another list");
        assert!(!verify(&p, &nd, &c0, &[false], &c1, &[false]), "LYING PROVER: flipped bits are another statement");
        let mut bad = p.clone();
        let n = bad.len();
        bad[n / 2] ^= 1;
        assert!(!verify(&bad, &nd, &c0, &[true], &c1, &[true]), "TAMPER: a flipped byte is refused");
    }

    /// ⛔ A2: a created entry whose nullifier IS a tag has no leaf; so has one created IN this record; an entry not yet made
    /// is not checked (its note did not exist).
    #[test]
    fn a2_a_spent_created_nullifier_has_no_leaf() {
        let r = rec(1);
        let spent = r.tags[0].0[13];
        assert!(prove_leaf(&[(spent, lanes(70))], lanes(1), &[true], &r).is_none(), "a created entry's spent nullifier");
        assert!(prove_leaf(&[(lanes(7), lanes(70)), (spent, lanes(71))], lanes(1), &[true, true], &r).is_none(), "one sinks the list");
        let made_here = r.outs[0].0[4];
        assert!(prove_leaf(&[(spent, made_here)], lanes(1), &[false], &r).is_none(), "made in this record and spent in it");
        let p = prove_leaf(&[(spent, lanes(71))], lanes(1), &[false], &r).expect("not yet made: not checked");
        let ap: AbsProof = postcard::from_bytes(&p).unwrap();
        assert_eq!(ap.f_end, vec![false], "an entry not made here stays uncreated");
    }

    /// ⭐ A3: leaves whose spans and bits meet merge; the merge is refused at either half's span; a GAP, another list and a
    /// flipped meeting bit do not merge.
    #[test]
    fn a3_meeting_leaves_merge_and_a_gap_does_not() {
        let e = vec![(lanes(7), lanes(70))];
        let nd = nfs_digest(&e);
        let c0 = lanes(1);
        let (x, y) = (rec(1), rec(2));
        let c1 = step_rec(&c0, &x);
        let c2 = step_rec(&c1, &y);
        let l = prove_leaf(&e, c0, &[true], &x).expect("left");
        let r = prove_leaf(&e, c1, &[true], &y).expect("right");
        let m = prove_merge(&l, &r).expect("meeting spans merge");
        assert!(verify(&m, &nd, &c0, &[true], &c2, &[true]), "the merge verifies at the joined span");
        assert!(!verify(&m, &nd, &c0, &[true], &c1, &[true]), "LYING PROVER: the left half's end");
        assert!(!verify(&m, &nd, &c1, &[true], &c2, &[true]), "LYING PROVER: the right half's start");
        let far = prove_leaf(&e, lanes(99), &[true], &y).expect("a leaf elsewhere");
        assert!(prove_merge(&l, &far).is_none(), "a GAP cannot be merged");
        let other = prove_leaf(&[(lanes(8), lanes(70))], c1, &[true], &y).expect("another list");
        assert!(prove_merge(&l, &other).is_none(), "two lists cannot be merged");
        let unmade = prove_leaf(&e, c1, &[false], &y).expect("the right half stated uncreated");
        assert!(prove_merge(&l, &unmade).is_none(), "a flipped meeting bit cannot be merged");
    }

    /// ⭐ A6 — THE CREATED BIT: a note made in record 2 of a four-record span sets its bit there; its nullifier as a tag of
    /// record 1 (before it existed) is not checked, as a tag of record 3 it has no proof; a carrier that STARTS after the
    /// note was made can never set the bit, so it is refused at the bit the spend wrapper will require.
    #[test]
    fn a6_the_created_bit_starts_the_checks_at_the_notes_own_record() {
        let c0 = lanes(1);
        let mut rs: Vec<Record> = (1..=4).map(rec).collect();
        let leaf = rs[1].outs[0].0[9]; // made in record 2
        let nf = rs[0].tags[0].0[5]; // a tag of record 1: before the note existed
        let e = vec![(nf, leaf)];
        let mut c = c0;
        let mut f = vec![false];
        let mut proofs = Vec::new();
        for r in &rs {
            let p = prove_leaf(&e, c, &f, r).expect("each record proves");
            let ap: AbsProof = postcard::from_bytes(&p).unwrap();
            f = ap.f_end.clone();
            c = step_rec(&c, r);
            proofs.push(p);
        }
        assert_eq!(f, vec![true], "the bit is set by the note's own record");
        let m01 = prove_merge(&proofs[0], &proofs[1]).expect("records 1-2");
        let m23 = prove_merge(&proofs[2], &proofs[3]).expect("records 3-4");
        let all = prove_merge(&m01, &m23).expect("records 1-4");
        assert!(verify(&all, &nfs_digest(&e), &c0, &[false], &c, &[true]), "made in the span, absent after");
        // the nullifier as a tag of record 3: no proof once the note exists
        rs[2].tags[0].0[0] = nf;
        let c2 = step_rec(&step_rec(&c0, &rs[0]), &rs[1]);
        assert!(prove_leaf(&e, c2, &[true], &rs[2]).is_none(), "spent after its creation: no leaf");
        // a carrier that starts after the creation cannot set the bit
        let late = prove_leaf(&e, c2, &[false], &rs[3]).expect("an uncreated statement proves");
        let ap: AbsProof = postcard::from_bytes(&late).unwrap();
        assert_eq!(ap.f_end, vec![false], "no later record makes the note again");
    }

    /// ⛔ A7 — THE ROLE IS BOUND: a tag chunk relabelled with the output role (so its tags would escape the checks) and an
    /// output chunk with no END have no leaf.
    #[test]
    fn a7_a_chunk_whose_role_is_not_its_place_has_no_leaf() {
        let e = vec![(lanes(7), lanes(70))];
        let mut r = rec(1);
        r.tags[0].1 = out_aux();
        assert!(prove_leaf(&e, lanes(1), &[true], &r).is_none(), "a tag chunk with the output role");
        let mut r = rec(1);
        r.outs[0].1 = out_aux();
        assert!(prove_leaf(&e, lanes(1), &[true], &r).is_none(), "a record's last chunk without END");
    }

    /// ⛔ A8 — A FORGED CREATION: a dishonest prover that forces the created bit for a leaf that is NOT among the record's
    /// outputs (a note that never existed) has no leaf; with the same bit forced for a leaf that IS there, it proves.
    #[test]
    fn a8_a_forced_created_bit_for_a_leaf_not_made_here_has_no_leaf() {
        let r = rec(1);
        let fake = lanes(424_242);
        assert!(prove_leaf_with(&[(lanes(7), fake)], lanes(1), &[false], &r, Some(&[true])).is_none(), "a note never made");
        let mut near = r.outs[0].0[3];
        near[7] += Fa4::ONE;
        assert!(prove_leaf_with(&[(lanes(7), near)], lanes(1), &[false], &r, Some(&[true])).is_none(), "one lane off");
        let real = r.outs[0].0[3];
        assert!(prove_leaf_with(&[(lanes(7), real)], lanes(1), &[false], &r, Some(&[true])).is_some(), "CALIBRATION: a real one");
    }

    /// ⭐ W1 — THE SPEND WRAPPER: a note made in record 2 of a three-record carrier over a list of two is spent by a proof
    /// that names only (nf, binder, leaf_commit, end); the door accepts it there and refuses another end, another binder,
    /// another leaf commitment, another nullifier (the list's OTHER entry, or a stranger) and a flipped byte; an entry whose
    /// note is not made in the span has no wrapper.
    #[test]
    fn w1_the_spend_wrapper_exposes_only_the_nullifier_and_the_end() {
        let rs: Vec<Record> = (1..=3).map(rec).collect();
        let leaf = rs[1].outs[0].0[6];
        let other_leaf = lanes(777); // never made
        let e = vec![(lanes(7), leaf), (lanes(8), other_leaf)];
        let mut c = lanes(1);
        let mut f = vec![false, false];
        let mut ps = Vec::new();
        for r in &rs {
            let p = prove_leaf(&e, c, &f, r).expect("each record proves");
            f = postcard::from_bytes::<AbsProof>(&p).unwrap().f_end;
            c = step_rec(&c, r);
            ps.push(p);
        }
        let m = prove_merge(&ps[0], &ps[1]).expect("1-2");
        let carrier = prove_merge(&m, &ps[2]).expect("1-3");
        let (binder, blind) = (lanes(31), lanes(32));
        let lc = leaf_commit(&leaf, &binder, &blind);
        let w = prove_spend(&e, 0, &carrier, binder, blind).expect("the made note's spend proves");
        eprintln!("[w1] wrapper: {} bytes, nvars {}", w.len(), postcard::from_bytes::<SpendProof>(&w).unwrap().nvars);
        assert!(verify_spend(&w, &lanes(7), &binder, &lc, &c), "the door accepts the spend");
        assert!(!verify_spend(&w, &lanes(7), &binder, &lc, &lanes(5)), "LYING PROVER: another end");
        assert!(!verify_spend(&w, &lanes(7), &lanes(33), &lc, &c), "LYING PROVER: another binder");
        assert!(!verify_spend(&w, &lanes(7), &binder, &lanes(34), &c), "LYING PROVER: another leaf commitment");
        assert!(!verify_spend(&w, &lanes(8), &binder, &lc, &c), "LYING PROVER: the list's other entry");
        assert!(!verify_spend(&w, &lanes(9), &binder, &lc, &c), "LYING PROVER: a stranger nullifier");
        let mut bad = w.clone();
        let n = bad.len();
        bad[n / 3] ^= 1;
        assert!(!verify_spend(&bad, &lanes(7), &binder, &lc, &c), "TAMPER: a flipped byte");
        assert!(prove_spend(&e, 1, &carrier, binder, blind).is_none(), "a note never made has no spend");
    }

    /// ⭐ J1 — ONE LIST THAT GROWS: note A (made in record 1) is carried alone; note B joins the list before record 2, which
    /// makes it; the joined carrier merges on, and BOTH notes are spent by wrappers over the one list. A join that states the
    /// new entry already created is another statement (refused).
    #[test]
    fn j1_a_list_grows_by_a_join_and_both_notes_spend() {
        let r1 = rec(1);
        let r2 = rec(2);
        let (la, lb) = (r1.outs[0].0[2], r2.outs[0].0[5]);
        let (a, b) = ((lanes(71), la), (lanes(72), lb));
        let c0 = lanes(1);
        let p1 = prove_leaf(&[a], c0, &[false], &r1).expect("record 1 makes A");
        let c1 = step_rec(&c0, &r1);
        let j = prove_join(&p1, &[a], &[b]).expect("B joins before the record that makes it");
        let both = [a, b];
        assert!(verify(&j, &nfs_digest(&both), &c0, &[false, false], &c1, &[true, false]), "the joined statement");
        assert!(!verify(&j, &nfs_digest(&both), &c0, &[false, true], &c1, &[true, true]), "LYING PROVER: the joined entry stated created");
        let p2 = prove_leaf(&both, c1, &[true, false], &r2).expect("record 2 makes B");
        let c2 = step_rec(&c1, &r2);
        let m = prove_merge(&j, &p2).expect("the joined carrier merges on");
        assert!(verify(&m, &nfs_digest(&both), &c0, &[false, false], &c2, &[true, true]), "both made in the span");
        for (idx, (nf, leaf)) in both.iter().enumerate() {
            let (binder, blind) = (lanes(40 + idx as u64), lanes(50 + idx as u64));
            let w = prove_spend(&both, idx, &m, binder, blind).expect("each note of the one list spends");
            assert!(verify_spend(&w, nf, &binder, &leaf_commit(leaf, &binder, &blind), &c2), "the door accepts the spend of entry {idx}");
        }
    }

    /// ⭐ A5 — THE CONSTANT: records merged as a binary counter reach a FIXED proof size (nvars per depth; a slope would show
    /// as nvars growing), every root verifies at its span and is refused one record short.
    #[test]
    fn a5_the_merge_reaches_a_fixed_size_at_depth() {
        let e = vec![(lanes(7), lanes(70)), (lanes(8), lanes(80))];
        let nd = nfs_digest(&e);
        let mut c = lanes(1);
        let mut ends = vec![c];
        let mut leaves = Vec::new();
        for i in 0..8u64 {
            let r = rec(i + 1);
            leaves.push(prove_leaf(&e, c, &[true, true], &r).expect("a leaf"));
            c = step_rec(&c, &r);
            ends.push(c);
        }
        let mut level = leaves;
        let mut span = 1usize;
        let mut sizes = Vec::new();
        while level.len() > 1 {
            level = level.chunks(2).map(|p| prove_merge(&p[0], &p[1]).expect("meeting spans merge")).collect();
            span *= 2;
            let ap: AbsProof = postcard::from_bytes(&level[0]).unwrap();
            sizes.push((span, ap.nvars, level[0].len()));
            eprintln!("[a5] depth {}: span {span} records, nvars {}, {} bytes", sizes.len(), ap.nvars, level[0].len());
            let t = [true, true];
            assert!(verify(&level[0], &nd, &ends[0], &t, &ends[span], &t), "the root of {span} records verifies at its span");
            assert!(!verify(&level[0], &nd, &ends[0], &t, &ends[span - 1], &t), "LYING PROVER: one record short is refused");
        }
        assert_eq!(sizes.len(), 3);
        assert_eq!(sizes[1].1, sizes[2].1, "the merge's size is a fixpoint from depth 2 on: {sizes:?}");
    }

    /// ⛔ A4 (DB-213c arm B's shape): a merge whose child is a valid leaf of ANOTHER span relabelled to this one is refused
    /// in circuit — the merge door checks the child under the merge's own parts, never the child's say-so.
    #[test]
    fn a4_a_child_of_another_span_is_refused_in_circuit() {
        let e = vec![(lanes(7), lanes(70))];
        let c0 = lanes(1);
        let (x, y) = (rec(1), rec(2));
        let c1 = step_rec(&c0, &x);
        let l = prove_leaf(&e, c0, &[true], &x).expect("left");
        let r = prove_leaf(&e, c1, &[true], &y).expect("right");
        let alien = prove_leaf(&e, lanes(55), &[true], &y).expect("an alien leaf");
        let mut ap: AbsProof = postcard::from_bytes(&alien).unwrap();
        let rr: AbsProof = postcard::from_bytes(&r).unwrap();
        ap.c_start = rr.c_start;
        ap.c_end = rr.c_end;
        let forged = postcard::to_allocvec(&ap).unwrap();
        assert!(prove_merge(&l, &forged).is_none(), "a relabelled child does not verify in circuit");
    }
}

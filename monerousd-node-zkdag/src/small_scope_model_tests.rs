// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! §PROOFS step 2 — SMALL-SCOPE EXHAUSTIVE MODEL CHECKS over the REAL ordering and set code.
//!
//! BORROWED-FROM the small-scope hypothesis (Jackson, Alloy) and explicit-state model checking (TLA+/TLC):
//! most protocol bugs show on tiny instances, so every instance up to a small bound is enumerated instead of
//! sampling big ones. Three explorers, each over production code paths, each with a planted-defect refuter
//! that must produce a counterexample (refutation before green):
//!
//! 1. GHOSTDAG: every DAG of genesis + ≤ 5 blocks (every block's parents any non-empty subset of the earlier
//!    blocks — redundant parents included, a hostile shape) × every arrival order a node can see (every
//!    linear extension) → one canonical order, one colouring, one blue score/work, one tip set, one virtual
//!    mergeset; the canonical order is a linear extension; every stored GHOSTDAG datum re-derives from the DAG.
//! 2. THE NULLIFIER SET DOOR (`SparseNfAcc::verify_and_insert`, the wire door for a carried copath): every
//!    sequence of ≤ 5 spend attempts over 3 nullifiers, each attempt a FRESH copath or a STALE one captured at
//!    an older root → a replay and a stale witness are refused, a fresh unspent nf is admitted, and the root
//!    is a function of the spent SET (every order reaching a set reaches one root, equal to the tree's).
//! 3. FIRST SPENDER WINS (`Dag::canonical_block_nullifiers` + `consensus::resolve_nullifier_conflicts`, the
//!    pair `Node` runs): every DAG of genesis + ≤ 4 blocks × every assignment of spends over 2 nullifiers ×
//!    every arrival order → one pruned set; every nullifier keeps exactly one spender, the canonical first.
//!
//! 4. RESTART (`Dag::add_anchor` + `add_ancestor_anchor` + `relink_selected_parents` + `rebuild_selected_chain_index`,
//!    the sequence `Node::restore_snapshot` → `install_block_window_span` runs): every DAG of genesis + ≤ 5 blocks ×
//!    every block as the checkpoint anchor × the window installed ascending AND descending → after the rest of the
//!    DAG re-arrives through `add_block`, the restored node holds the view the never-restarted node holds (canonical
//!    order with every block's (sp, blue score, blue work, chain depth), tips, selected tip, virtual mergeset).
//!
//! Bounds: ≤ 60 s and ≤ 500 MB each in the pin profile. Families: pins-core.

use std::collections::{BTreeMap, BTreeSet};

use crate::block::{Block, BlockId};
use crate::dag::Dag;
use crate::ghostdag::canonical_merge_order_tests::blk;
use crate::nf_sparse::{RefSparseNf, SparseNfAcc};

/// Every DAG shape over `n` non-genesis blocks: `shape[i]` = the parents of block `i + 1` as indexes into
/// `0..=i` (0 = genesis), every non-empty subset. Count = Π_{i=1..n} (2^i − 1) (n = 5: 9 765).
fn dag_shapes(n: usize) -> Vec<Vec<Vec<usize>>> {
    let mut shapes: Vec<Vec<Vec<usize>>> = vec![Vec::new()];
    for i in 1..=n {
        let mut next = Vec::new();
        for s in &shapes {
            for mask in 1u32..(1u32 << i) {
                let parents: Vec<usize> = (0..i).filter(|b| mask & (1 << b) != 0).collect();
                let mut t = s.clone();
                t.push(parents);
                next.push(t);
            }
        }
        shapes = next;
    }
    shapes
}

/// Every arrival order of blocks `1..=n` in which each block arrives after its parents (every order a node
/// can actually admit them in — `add_block` refuses a missing parent).
fn arrival_orders(shape: &[Vec<usize>]) -> Vec<Vec<usize>> {
    fn go(shape: &[Vec<usize>], placed: &mut Vec<usize>, held: &mut BTreeSet<usize>, out: &mut Vec<Vec<usize>>) {
        if placed.len() == shape.len() {
            out.push(placed.clone());
            return;
        }
        for b in 1..=shape.len() {
            if held.contains(&b) || !shape[b - 1].iter().all(|p| held.contains(p)) {
                continue;
            }
            held.insert(b);
            placed.push(b);
            go(shape, placed, held, out);
            placed.pop();
            held.remove(&b);
        }
    }
    let mut out = Vec::new();
    let mut held: BTreeSet<usize> = [0usize].into_iter().collect();
    go(shape, &mut Vec::new(), &mut held, &mut out);
    out
}

/// The blocks of one shape, built once against a reference DAG fed in index order, so every replay below
/// carries the identical bytes (identical ids) — only the arrival order differs.
fn build_blocks(shape: &[Vec<usize>]) -> (Block, Vec<Block>, Vec<BlockId>) {
    let genesis = crate::node::tests::genesis_block();
    let mut reference = Dag::new();
    let g = reference.add_block(genesis.clone()).expect("genesis");
    let mut ids = vec![g];
    let mut blocks = Vec::new();
    for (i, parents) in shape.iter().enumerate() {
        let b = blk(parents.iter().map(|p| ids[*p]).collect(), &reference, (i + 1) as u64);
        let id = reference
            .add_block(b.clone())
            .unwrap_or_else(|e| panic!("shape {shape:?}: block {} refused in index order: {e:?}", i + 1));
        ids.push(id);
        blocks.push(b);
    }
    (genesis, blocks, ids)
}

fn replay(genesis: &Block, blocks: &[Block], order: &[usize], shape: &[Vec<usize>]) -> Dag {
    let mut dag = Dag::new();
    dag.add_block(genesis.clone()).expect("genesis");
    for b in order {
        dag.add_block(blocks[b - 1].clone())
            .unwrap_or_else(|e| panic!("shape {shape:?} order {order:?}: block {b} refused: {e:?}"));
    }
    dag
}

/// What two nodes holding the same DAG must agree on, whatever order its blocks arrived in.
#[derive(PartialEq, Debug)]
struct GhostdagView {
    canonical: Vec<(BlockId, Option<BlockId>, u64, u128)>,
    tips: Vec<BlockId>,
    selected_tip: Option<BlockId>,
    virtual_blues: Vec<BlockId>,
    virtual_reds: Vec<BlockId>,
    virtual_score: u64,
    virtual_work: u128,
}

fn real_view(dag: &Dag) -> Vec<BlockId> {
    dag.canonical_order()
}

/// ⛔ PLANTED DEFECT for the refuter: the pre-fix ordering — concurrent blocks tie-broken by `topo_order`, the
/// local RECEIVE counter — instead of the content id.
fn arrival_tiebreak_view(dag: &Dag) -> Vec<BlockId> {
    let mut ids = dag.canonical_order();
    ids.sort_by_key(|id| {
        let n = dag.get(id).expect("held");
        (n.blue_work, n.topo_order)
    });
    ids
}

fn ghostdag_view(dag: &Dag, order_fn: fn(&Dag) -> Vec<BlockId>) -> GhostdagView {
    let canonical = order_fn(dag)
        .into_iter()
        .map(|id| {
            let n = dag.get(&id).expect("ordered block held");
            (id, n.selected_parent, n.blue_score, n.blue_work)
        })
        .collect();
    let mut tips = dag.tips();
    tips.sort();
    let v = dag.ghostdag_data(&tips);
    GhostdagView {
        canonical,
        tips,
        selected_tip: dag.selected_tip(),
        virtual_blues: v.mergeset_blues,
        virtual_reds: v.mergeset_reds,
        virtual_score: v.blue_score,
        virtual_work: v.blue_work,
    }
}

/// Per-DAG laws that need no second node: the canonical order is a linear extension of the DAG holding every
/// block once, and every stored GHOSTDAG datum is what `ghostdag_data` re-derives from the DAG now (state is a
/// function of the chain, never of the moment a block arrived).
fn single_dag_laws(dag: &Dag, ids: &[BlockId], shape: &[Vec<usize>], order: &[usize]) -> Result<(), String> {
    let canon = dag.canonical_order();
    let pos: BTreeMap<BlockId, usize> = canon.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    if canon.len() != ids.len() || pos.len() != ids.len() {
        return Err(format!("shape {shape:?} order {order:?}: canonical order holds {} of {} blocks", pos.len(), ids.len()));
    }
    for (i, parents) in shape.iter().enumerate() {
        for p in parents {
            if pos[&ids[*p]] >= pos[&ids[i + 1]] {
                return Err(format!("shape {shape:?} order {order:?}: parent {p} ordered after its child {}", i + 1));
            }
        }
        let n = dag.get(&ids[i + 1]).expect("held");
        let gd = dag.ghostdag_data(&n.header.parents);
        if (Some(gd.selected_parent), gd.blue_score, gd.blue_work) != (n.selected_parent, n.blue_score, n.blue_work) {
            return Err(format!(
                "shape {shape:?} order {order:?}: block {} stores (sp, score, work) {:?} but the DAG re-derives {:?}",
                i + 1,
                (n.selected_parent, n.blue_score, n.blue_work),
                (Some(gd.selected_parent), gd.blue_score, gd.blue_work)
            ));
        }
    }
    Ok(())
}

/// One shape over the given arrival orders: every order an independent `Dag`, every view compared to the first.
fn check_ghostdag_shape(shape: &[Vec<usize>], orders: Vec<Vec<usize>>, order_fn: fn(&Dag) -> Vec<BlockId>) -> Result<usize, String> {
    let (genesis, blocks, ids) = build_blocks(shape);
    let mut first: Option<(Vec<usize>, GhostdagView)> = None;
    let mut runs = 0usize;
    for order in orders {
        let dag = replay(&genesis, &blocks, &order, shape);
        single_dag_laws(&dag, &ids, shape, &order)?;
        let view = ghostdag_view(&dag, order_fn);
        runs += 1;
        match &first {
            None => first = Some((order, view)),
            Some((o0, v0)) if *v0 != view => {
                return Err(format!(
                    "shape {shape:?}: arrival {o0:?} and {order:?} give two views of one DAG\n  {v0:?}\n  {view:?}"
                ))
            }
            _ => {}
        }
    }
    Ok(runs)
}

/// Explorer 1. `Err` = the first counterexample (shape, the two arrival orders, the two views).
fn explore_ghostdag(n: usize, order_fn: fn(&Dag) -> Vec<BlockId>) -> Result<(usize, usize), String> {
    let (mut shapes_seen, mut runs) = (0usize, 0usize);
    for shape in dag_shapes(n) {
        let orders = arrival_orders(&shape);
        runs += check_ghostdag_shape(&shape, orders, order_fn)?;
        shapes_seen += 1;
    }
    Ok((shapes_seen, runs))
}

/// ⭐⭐⭐ ONE ORDER WHICHEVER ARRIVAL ORDER — exhaustively, every DAG of 6 blocks.
///
/// TWO-PARTY-REVIEWED: each arrival order is an independent `Dag` (a node of its own) and every pair of them is
/// compared directly; the claim is cross-node and so is the assertion.
#[test]
fn small_scope_every_dag_of_six_blocks_orders_and_colours_identically_under_every_arrival_order() {
    let t = std::time::Instant::now();
    let (shapes, runs) = explore_ghostdag(5, real_view).unwrap_or_else(|cx| panic!("COUNTEREXAMPLE: {cx}"));
    eprintln!("[small-scope ghostdag] {shapes} DAG shapes, {runs} arrival orders, {:?}", t.elapsed());
    assert_eq!(shapes, 9_765, "the explorer must visit every shape of genesis + 5 blocks");
}

/// REFUTER: the explorer must find the receive-order tie-break (the defect `Dag::mergeset`'s ⛔ note records).
#[test]
fn small_scope_refuter_the_explorer_catches_a_receive_order_tiebreak() {
    let cx = explore_ghostdag(3, arrival_tiebreak_view).expect_err("a receive-order tie-break must be caught");
    assert!(cx.contains("two views of one DAG"), "the counterexample is a cross-node disagreement: {cx}");
}

// ───────────────────────── explorer 2: the nullifier-set door ─────────────────────────

const NFS: [[u8; 32]; 3] = {
    let mut t = [[0u8; 32]; 3];
    t[0][0] = 0x11;
    t[0][31] = 0xA0;
    t[1][0] = 0x22;
    t[1][31] = 0x0B;
    t[2][0] = 0x33;
    t[2][31] = 0xC7;
    t
};

/// The door under test: the production wire door, or a planted defect for the refuter.
type Door = fn(&mut SparseNfAcc, &[u8; 32], &[crate::spend_frontier::Digest4]) -> bool;

fn real_door(acc: &mut SparseNfAcc, nf: &[u8; 32], cp: &[crate::spend_frontier::Digest4]) -> bool {
    acc.verify_and_insert(nf, cp).is_ok()
}

/// ⛔ PLANTED DEFECT: a door that folds the carried copath without checking it against the current root.
fn unchecked_door(acc: &mut SparseNfAcc, nf: &[u8; 32], cp: &[crate::spend_frontier::Digest4]) -> bool {
    acc.insert_from_own_copath(nf, cp);
    true
}

struct SetState {
    tree: RefSparseNf,
    acc: SparseNfAcc,
    spent: BTreeSet<usize>,
    /// Copaths captured earlier: (nf index, root they were built on, copath).
    captured: Vec<(usize, [u8; 32], Vec<crate::spend_frontier::Digest4>)>,
}

fn explore_set(state: SetState, depth: usize, door: Door, roots: &mut BTreeMap<BTreeSet<usize>, [u8; 32]>, visits: &mut usize, trail: &mut Vec<String>) -> Result<(), String> {
    *visits += 1;
    let root = state.acc.root_bytes();
    if let Some(r) = roots.get(&state.spent) {
        if *r != root {
            return Err(format!("spent set {:?} reached two roots; trail {trail:?}", state.spent));
        }
    } else {
        roots.insert(state.spent.clone(), root);
    }
    if depth == 0 {
        return Ok(());
    }
    for nf_i in 0..NFS.len() {
        // a fresh copath from the honest tree at the current root (for a spent nf: the replay's member copath)
        let mut fresh_tree = state.tree.clone();
        let fresh_cp = fresh_tree.advance_one(&NFS[nf_i]);
        let mut attempts: Vec<(String, [u8; 32], Vec<crate::spend_frontier::Digest4>)> =
            vec![(format!("fresh nf{nf_i}"), root, fresh_cp.clone())];
        for (ci, (c_nf, c_root, cp)) in state.captured.iter().enumerate() {
            if *c_nf == nf_i && *c_root != root {
                attempts.push((format!("stale#{ci} nf{nf_i}"), *c_root, cp.clone()));
            }
        }
        for (label, built_on, cp) in attempts {
            let mut acc = state.acc;
            let admitted = door(&mut acc, &NFS[nf_i], &cp);
            let should = !state.spent.contains(&nf_i) && built_on == root;
            trail.push(label.clone());
            if admitted != should {
                return Err(format!("{label}: door admitted={admitted}, the set says {should}; trail {trail:?}"));
            }
            if !admitted && acc.root_bytes() != root {
                return Err(format!("{label}: a refused attempt moved the root; trail {trail:?}"));
            }
            let next = if admitted {
                let mut spent = state.spent.clone();
                spent.insert(nf_i);
                SetState { tree: fresh_tree.clone(), acc, spent, captured: state.captured.clone() }
            } else {
                SetState { tree: state.tree.clone(), acc: state.acc, spent: state.spent.clone(), captured: state.captured.clone() }
            };
            let mut next = next;
            if label.starts_with("fresh") && !state.spent.contains(&nf_i) {
                next.captured.push((nf_i, root, fresh_cp.clone()));
            }
            explore_set(next, depth - 1, door, roots, visits, trail)?;
            trail.pop();
        }
    }
    Ok(())
}

fn run_set_explorer(depth: usize, door: Door) -> Result<(usize, usize), String> {
    let mut roots = BTreeMap::new();
    let mut visits = 0usize;
    let s = SetState { tree: RefSparseNf::new(), acc: SparseNfAcc::new(), spent: BTreeSet::new(), captured: Vec::new() };
    explore_set(s, depth, door, &mut roots, &mut visits, &mut Vec::new())?;
    // every subset of the 3 nullifiers is reachable within depth 3, and each reached one root
    Ok((visits, roots.len()))
}

/// ⭐⭐⭐ A SPENT NOTE IS REFUSED BY THE SET, NOT BY LUCK (Zcash nullifiers) — every replay order, exhaustively.
#[test]
fn small_scope_the_nullifier_door_refuses_every_replay_and_stale_witness_in_every_order() {
    let t = std::time::Instant::now();
    let (visits, sets) = run_set_explorer(6, real_door).unwrap_or_else(|cx| panic!("COUNTEREXAMPLE: {cx}"));
    eprintln!("[small-scope nf door] {visits} states, {sets} spent sets, {:?}", t.elapsed());
    assert_eq!(sets, 8, "every subset of the 3 nullifiers must be reached (2^3)");
}

/// REFUTER: a door that skips the root check must be caught admitting a replay or a stale witness.
#[test]
fn small_scope_refuter_the_explorer_catches_an_unchecked_copath_door() {
    let cx = run_set_explorer(3, unchecked_door).expect_err("an unchecked door must be caught");
    assert!(cx.contains("door admitted=true, the set says false"), "the counterexample is an admitted replay/stale witness: {cx}");
}

// ───────────────────────── explorer 3: first spender wins ─────────────────────────

fn canonical_ids(dag: &Dag) -> Vec<BlockId> {
    dag.canonical_order()
}

/// Explorer 3. `ordered_fn(dag, arrival ids)` = the block order the resolver is fed.
fn explore_first_spender(n: usize, ordered_fn: fn(&Dag, &[BlockId]) -> Vec<BlockId>) -> Result<(usize, usize), String> {
    let all_masks: Vec<u64> = (0..1u64 << (2 * n)).collect(); // each block spends a subset of {nf0, nf1}: 2 bits per block
    let (mut checked, mut runs) = (0usize, 0usize);
    for shape in dag_shapes(n) {
        let orders = arrival_orders(&shape);
        let (c, r) = check_first_spender_shape(&shape, orders, &all_masks, ordered_fn)?;
        checked += c;
        runs += r;
    }
    Ok((checked, runs))
}

/// One shape × the given arrival orders × the given spend masks (bit `2(i−1)+k` = block `i` spends `nf_k`).
fn check_first_spender_shape(
    shape: &[Vec<usize>],
    orders: Vec<Vec<usize>>,
    masks: &[u64],
    ordered_fn: fn(&Dag, &[BlockId]) -> Vec<BlockId>,
) -> Result<(usize, usize), String> {
    let nf = |k: usize| -> [u8; 32] { NFS[k] };
    let (mut checked, mut runs) = (0usize, 0usize);
    {
        let (genesis, blocks, ids) = build_blocks(shape);
        let mut first: Option<(Vec<usize>, Vec<Vec<(BlockId, [u8; 32])>>)> = None;
        for order in orders {
            let dag = replay(&genesis, &blocks, &order, shape);
            let arrival: Vec<BlockId> = std::iter::once(ids[0]).chain(order.iter().map(|b| ids[*b])).collect();
            let fed = ordered_fn(&dag, &arrival);
            let mut per_mask = Vec::with_capacity(masks.len());
            for &m in masks {
                let spends = |id: &BlockId| -> Vec<[u8; 32]> {
                    match ids.iter().position(|x| x == id) {
                        Some(i) if i > 0 => (0..2).filter(|k| m >> (2 * (i - 1) + k) & 1 == 1).map(nf).collect(),
                        _ => Vec::new(),
                    }
                };
                // the pair `Node` runs: canonical_block_nullifiers' shape, fed in `fed` order
                let ordered: Vec<(BlockId, Vec<[u8; 32]>)> = fed.iter().map(|id| (*id, spends(id))).collect();
                let pruned = crate::consensus::resolve_nullifier_conflicts(&ordered);
                // law: every nullifier keeps exactly ONE spender — the first in canonical order
                let canon = dag.canonical_order();
                for k in 0..2 {
                    let spenders: Vec<BlockId> = canon.iter().filter(|id| spends(id).contains(&nf(k))).copied().collect();
                    let kept: Vec<BlockId> = spenders
                        .iter()
                        .filter(|id| !pruned.iter().any(|p| p.block == **id && p.nullifier == nf(k)))
                        .copied()
                        .collect();
                    if !spenders.is_empty() && kept != vec![spenders[0]] {
                        return Err(format!(
                            "shape {shape:?} arrival {order:?} mask {m:#b}: nf{k} keeps {kept:?}, the canonical first spender is {:?}",
                            spenders[0]
                        ));
                    }
                }
                let mut p: Vec<(BlockId, [u8; 32])> = pruned.iter().map(|p| (p.block, p.nullifier)).collect();
                p.sort();
                per_mask.push(p);
                checked += 1;
            }
            runs += 1;
            match &first {
                None => first = Some((order, per_mask)),
                Some((o0, p0)) if *p0 != per_mask => {
                    return Err(format!("shape {shape:?}: arrival {o0:?} and {order:?} prune different spends"));
                }
                _ => {}
            }
        }
    }
    Ok((checked, runs))
}

/// ⭐⭐⭐ NO NOTE SPENT TWICE, ONE WINNER ON EVERY NODE — every DAG of 5 blocks × every spend assignment × every
/// arrival order. TWO-PARTY-REVIEWED: every arrival order is its own `Dag`, and their pruned sets are compared.
#[test]
fn small_scope_first_spender_wins_identically_on_every_dag_of_five_blocks() {
    let t = std::time::Instant::now();
    let (checked, runs) =
        explore_first_spender(4, |dag, _| canonical_ids(dag)).unwrap_or_else(|cx| panic!("COUNTEREXAMPLE: {cx}"));
    eprintln!("[small-scope first spender] {checked} (DAG, order, spends) cases over {runs} replays, {:?}", t.elapsed());
    assert_eq!(runs, dag_shapes(4).iter().map(|s| arrival_orders(s).len()).sum::<usize>());
}

/// REFUTER: a resolver fed the ARRIVAL order (a node trusting the order packets came in) must be caught.
#[test]
fn small_scope_refuter_the_explorer_catches_a_resolver_fed_arrival_order() {
    let cx = explore_first_spender(2, |_, arrival| arrival.to_vec()).expect_err("arrival-order resolution must be caught");
    assert!(cx.contains("canonical first spender") || cx.contains("prune different spends"), "{cx}");
}

// ───────────────────────── the seeded hunter: past the exhaustive bound ─────────────────────────

/// `SIM_SEED` (decimal or `0x` hex), the farm's per-run seed — the same parse as `harness::netsim`'s seed site
/// (that module is in another test family); an unparsable value is refused, never read as the default.
fn sim_seed(default: u64) -> u64 {
    match std::env::var("SIM_SEED") {
        Err(_) => default,
        Ok(s) => {
            let t = s.trim();
            let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(&h.replace('_', ""), 16).ok(),
                None => t.replace('_', "").parse().ok(),
            };
            v.unwrap_or_else(|| panic!("SIM_SEED={s:?} is not a decimal or 0x-hex u64"))
        }
    }
}

/// splitmix64 (Steele, Lea, Flood) — a test-only draw source; nothing here is key material.
struct Draw(u64);
impl Draw {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A random DAG of `n` blocks: each names 1–3 distinct parents among the 4 blocks before it (a DAG of width
/// ≤ 4, the shape a mesh produces — and redundant parents stay possible).
fn random_shape(d: &mut Draw, n: usize) -> Vec<Vec<usize>> {
    (1..=n)
        .map(|i| {
            let lo = i.saturating_sub(4);
            let want = 1 + d.below(3);
            let mut ps: BTreeSet<usize> = BTreeSet::new();
            while ps.len() < want.min(i - lo) {
                ps.insert(lo + d.below(i - lo));
            }
            ps.into_iter().collect()
        })
        .collect()
}

/// A uniformly drawn ready block at every step — a random arrival order a node can admit.
fn random_arrival(d: &mut Draw, shape: &[Vec<usize>]) -> Vec<usize> {
    let mut held: BTreeSet<usize> = [0usize].into_iter().collect();
    let mut order = Vec::with_capacity(shape.len());
    while order.len() < shape.len() {
        let ready: Vec<usize> =
            (1..=shape.len()).filter(|b| !held.contains(b) && shape[b - 1].iter().all(|p| held.contains(p))).collect();
        let b = ready[d.below(ready.len())];
        held.insert(b);
        order.push(b);
    }
    order
}

/// A random walk over the nullifier door: `steps` attempts over `nfs` seeded nullifiers, each a fresh copath or
/// a captured one (stale once any insert followed it); the same laws as explorer 2.
fn random_door_walk(d: &mut Draw, nfs: usize, steps: usize) -> Result<(), String> {
    let tags: Vec<[u8; 32]> = (0..nfs)
        .map(|_| {
            let mut t = [0u8; 32];
            for c in t.chunks_mut(8) {
                c.copy_from_slice(&d.next().to_le_bytes());
            }
            t
        })
        .collect();
    let (mut tree, mut acc) = (RefSparseNf::new(), SparseNfAcc::new());
    let mut spent: BTreeSet<usize> = BTreeSet::new();
    let mut captured: Vec<(usize, [u8; 32], Vec<crate::spend_frontier::Digest4>)> = Vec::new();
    let mut roots: BTreeMap<BTreeSet<usize>, [u8; 32]> = BTreeMap::new();
    for step in 0..steps {
        let root = acc.root_bytes();
        if *roots.entry(spent.clone()).or_insert(root) != root {
            return Err(format!("step {step}: spent set {spent:?} reached two roots"));
        }
        let i = d.below(nfs);
        let mut fresh_tree = tree.clone();
        let fresh_cp = fresh_tree.advance_one(&tags[i]);
        let mine: Vec<usize> = (0..captured.len()).filter(|c| captured[*c].0 == i).collect();
        let (built_on, cp, fresh) = if mine.is_empty() || d.below(2) == 0 {
            (root, fresh_cp.clone(), true)
        } else {
            let c = &captured[mine[d.below(mine.len())]];
            (c.1, c.2.clone(), false)
        };
        let mut next = acc;
        let admitted = real_door(&mut next, &tags[i], &cp);
        let should = !spent.contains(&i) && built_on == root;
        if admitted != should {
            return Err(format!("step {step}: nf{i} fresh={fresh} admitted={admitted}, the set says {should}"));
        }
        if fresh && !spent.contains(&i) {
            captured.push((i, root, fresh_cp));
        }
        if admitted {
            acc = next;
            tree = fresh_tree;
            spent.insert(i);
        } else if next.root_bytes() != root {
            return Err(format!("step {step}: a refused attempt moved the root"));
        }
    }
    Ok(())
}

/// ⭐ THE FARM HUNTER (`SIM_SEED` per run): the same three laws past the exhaustive bound — 40 random DAGs of 9
/// blocks × 24 random arrival orders (ordering + colouring + 64 random spend assignments over 2 nullifiers), and
/// 8 random door walks of 40 attempts over 5 nullifiers. Each failure prints the seed that reproduces it.
#[test]
fn small_scope_seeded_hunter_past_the_exhaustive_bound() {
    let seed = sim_seed(0x5EED_0001);
    let t = std::time::Instant::now();
    let mut d = Draw(seed);
    for _ in 0..40 {
        let shape = random_shape(&mut d, 8);
        let orders: Vec<Vec<usize>> = (0..24).map(|_| random_arrival(&mut d, &shape)).collect();
        check_ghostdag_shape(&shape, orders.clone(), real_view).unwrap_or_else(|cx| panic!("SIM_SEED={seed:#x} COUNTEREXAMPLE: {cx}"));
        let masks: Vec<u64> = (0..64).map(|_| d.next() & 0xFFFF).collect();
        check_first_spender_shape(&shape, orders, &masks, |dag, _| canonical_ids(dag))
            .unwrap_or_else(|cx| panic!("SIM_SEED={seed:#x} COUNTEREXAMPLE: {cx}"));
    }
    for _ in 0..8 {
        random_door_walk(&mut d, 5, 40).unwrap_or_else(|cx| panic!("SIM_SEED={seed:#x} COUNTEREXAMPLE: {cx}"));
    }
    eprintln!("[small-scope hunter] SIM_SEED={seed:#x} green in {:?}", t.elapsed());
}

// ───────────────────────── explorer 4: restart from a checkpoint anchor + the block window ─────────────────────────

/// The step after the window re-enters the DAG: production's, or a planted defect for the refuter.
type Relink = fn(&mut Dag, usize, &BlockId);

/// `install_block_window_span`'s tail, verbatim in effect: relink, and rebuild the chain index when anything re-entered —
/// then the restore's next step (`Node::restore`, after `install_block_window_span`): the re-installed span is this
/// node's OWN history re-linked below its checkpoint anchor, so the anchor's held past is SETTLED
/// (`settle_connected_past`, DB-282 / G1d). Lane stable 2026-10-30: the model stopped at the relink, so it restored a node
/// production no longer builds — every late sibling of the anchor stood only on unsettled history and was refused
/// (`BelowSettledBase`), the counterexample this explorer's red pin reported since 2026-10-24.
fn real_relink(dag: &mut Dag, installed: usize, anchor: &BlockId) {
    dag.relink_selected_parents();
    if installed > 0 {
        dag.rebuild_selected_chain_index();
    }
    dag.settle_connected_past(anchor);
}

/// ⛔ PLANTED DEFECT for the refuter: the relink skipped — the anchor keeps its trust-root `None` selected parent.
fn no_relink(_: &mut Dag, _: usize, _: &BlockId) {}

/// Every block of one DAG held twice over: the view (`ghostdag_view`) plus each canonical block's chain depth.
fn restart_view(dag: &Dag) -> (GhostdagView, Vec<u64>) {
    let depths = dag.canonical_order().iter().map(|id| dag.get(id).expect("held").selected_chain_len).collect();
    (ghostdag_view(dag, real_view), depths)
}

/// One shape: a node restored at every anchor (window both ways) against a never-restarted node holding the SAME blocks.
/// With `concurrent` false the blocks after the restart are the anchor's future whose whole past the restored node holds
/// and whose parents are an antichain (what an honest producer builds: its tips) — the restore law; with `concurrent`
/// true they are every other block of the DAG — the anchor's late-arriving siblings and hostile redundant-parent blocks
/// too, which every from-genesis node admits (F2-red-found-20261024, the DB-282 settled-base con).
fn check_restart_shape(shape: &[Vec<usize>], relink: Relink, concurrent: bool) -> Result<usize, String> {
    let (genesis, blocks, ids) = build_blocks(shape);
    let full = replay(&genesis, &blocks, &(1..=shape.len()).collect::<Vec<_>>(), shape);
    // every block's strict ancestors (genesis = 0 included), by index
    let mut ancestors: Vec<BTreeSet<usize>> = vec![BTreeSet::new()];
    for parents in shape {
        let mut a = BTreeSet::new();
        for p in parents {
            a.insert(*p);
            a.extend(ancestors[*p].iter().copied());
        }
        ancestors.push(a);
    }
    let mut runs = 0usize;
    for anchor in 1..=shape.len() {
        // the window: the anchor's strict past above genesis (what the checkpoint counted)
        let mut past = BTreeSet::new();
        let mut stack = shape[anchor - 1].clone();
        while let Some(b) = stack.pop() {
            if b != 0 && past.insert(b) {
                stack.extend(shape[b - 1].iter().copied());
            }
        }
        let mut after: Vec<usize> = Vec::new();
        for b in (1..=shape.len()).filter(|b| *b != anchor && !past.contains(b)) {
            let known = |p: &usize| *p == 0 || *p == anchor || past.contains(p) || after.contains(p);
            let descends = shape[b - 1].iter().any(|p| *p == anchor || after.contains(p));
            let antichain = shape[b - 1].iter().all(|p| shape[b - 1].iter().all(|q| !ancestors[*q].contains(p)));
            if concurrent || (descends && antichain && shape[b - 1].iter().all(known)) {
                after.push(b);
            }
        }
        let mut held: Vec<usize> = past.iter().copied().chain([anchor]).chain(after.iter().copied()).collect();
        held.sort();
        let live = replay(&genesis, &blocks, &held, shape);
        let want = restart_view(&live);
        for descending in [false, true] {
            let mut dag = Dag::new();
            dag.add_block(genesis.clone()).expect("genesis");
            let a = full.get(&ids[anchor]).expect("held");
            if !dag.add_anchor(blocks[anchor - 1].clone(), a.blue_work, a.blue_score, a.selected_chain_len) {
                return Err(format!("shape {shape:?}: anchor {anchor} refused"));
            }
            let mut window: Vec<usize> = past.iter().copied().collect();
            window.sort_by_key(|b| (full.get(&ids[*b]).expect("held").blue_score, ids[*b]));
            if descending {
                window.reverse();
            }
            let mut installed = 0usize;
            for b in &window {
                let n = full.get(&ids[*b]).expect("held");
                if dag.add_ancestor_anchor(n.header.clone(), n.tx_ids.clone(), n.blue_work, n.blue_score, n.selected_parent) {
                    installed += 1;
                }
            }
            relink(&mut dag, installed, &ids[anchor]);
            for b in &after {
                if let Err(e) = dag.add_block(blocks[b - 1].clone()) {
                    return Err(format!(
                        "shape {shape:?} anchor {anchor} descending={descending}: the restored node refuses block {b} the live node holds: {e:?}"
                    ));
                }
            }
            let got = restart_view(&dag);
            if got != want {
                return Err(format!(
                    "shape {shape:?} anchor {anchor} descending={descending}: the restored node and the live node disagree\n  live     {want:?}\n  restored {got:?}"
                ));
            }
            runs += 1;
        }
    }
    Ok(runs)
}

/// Explorer 4. `Err` = the first counterexample (shape, anchor, window order, the two views).
fn explore_restart(n: usize, relink: Relink, concurrent: bool) -> Result<(usize, usize), String> {
    let (mut shapes_seen, mut runs) = (0usize, 0usize);
    for shape in dag_shapes(n) {
        runs += check_restart_shape(&shape, relink, concurrent)?;
        shapes_seen += 1;
    }
    Ok((shapes_seen, runs))
}

/// ⭐⭐⭐ A RESTART CHANGES NOTHING — exhaustively, every DAG of genesis + 5 blocks, every block as the checkpoint anchor,
/// the blocks after the restart honest (antichain parents) and in the anchor's future (the rest: the red pin below).
///
/// TWO-PARTY-REVIEWED: the restored `Dag` and the never-restarted `Dag` are independent nodes compared directly; the
/// claim is cross-node (a resumed node and its peer) and so is the assertion.
#[test]
fn small_scope_a_node_restored_from_any_checkpoint_anchor_holds_the_live_view_on_every_dag_of_five_blocks() {
    let t = std::time::Instant::now();
    let (shapes, runs) = explore_restart(5, real_relink, false).unwrap_or_else(|cx| panic!("COUNTEREXAMPLE: {cx}"));
    eprintln!("[small-scope restart] {shapes} DAG shapes, {runs} restores, {:?}", t.elapsed());
    assert_eq!(shapes, 9_765, "the explorer must visit every shape of genesis + 5 blocks");
    assert_eq!(runs, 9_765 * 5 * 2, "every block as the anchor, the window both ways");
}

/// REFUTER: the explorer must find a restore that skips the relink.
#[test]
fn small_scope_refuter_the_explorer_catches_a_restore_without_the_relink() {
    let cx = explore_restart(2, no_relink, false).expect_err("a restore without the relink must be caught");
    assert!(cx.contains("disagree"), "the counterexample is a restored-vs-live disagreement: {cx}");
}

/// ⛔ RED (F2-red-found-20261024, G1 restart changes state): a block that arrives AFTER the restart standing only on the
/// anchor's past — a sibling of the checkpoint anchor every from-genesis node admits and merges — is refused by the
/// restored node (`DagError::BelowSettledBase`, the DB-282 rule's own stated con), so the restored node and its peer
/// hold two DAGs. A hostile block naming the anchor AND a block of its past (a redundant parent) is refused the same way
/// (`MergesPreAnchorHistory`) while every from-genesis node admits it — Kaspa refuses such a block on EVERY node
/// (parents must be an antichain). MEASURED 2026-10-24 (scratchpad/verify/small-scope-restart-3.log): the first
/// counterexamples are genesis + 2 siblings, anchor 1, block 2 refused; and [[0],[0],[0],[0],[0,1]], anchor 1, block 5. Kaspa's `check_pruning_violation` refuses only below the PRUNING
/// point, which sits past the merge-depth bound so no valid block can stand below it; the checkpoint anchor is the
/// shallow fold anchor. Smallest scope: genesis + 3 blocks.
#[test]
fn small_scope_red_a_restored_node_admits_every_late_sibling_of_its_anchor_a_live_node_admits() {
    let (shapes, runs) = explore_restart(3, real_relink, true).unwrap_or_else(|cx| panic!("COUNTEREXAMPLE: {cx}"));
    assert_eq!((shapes, runs), (21, 21 * 3 * 2));
}

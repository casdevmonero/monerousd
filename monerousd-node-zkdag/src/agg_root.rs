// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE LEVEL AGGREGATE, MILESTONE 2 — THE NODE'S SEAM TO THE PROOF TREE (lanes agg + speed5, 2026-11-15;
//! docs/LEVEL-AGGREGATE-SPEC-20261115.md §11, node piece F).
//!
//! WHAT CHANGES FOR A PEER. Milestone 1 left a peer pulling every aggregated payment's cores (about 36 KB a payment) and
//! verifying one openings table a block. In the tree a payment's three carriers are verified INSIDE a leaf proof by the
//! node that held it, the producer merges the leaves, and a peer holds the payment's STATEMENT (the public inputs of
//! today's three carrier checks, every one of them a field the transaction already carries) and verifies ONE root proof
//! a block over the statements in carried order. More nodes then means more leaf provers, which is the only way settled
//! throughput rises with the node count (spec §0).
//!
//! THIS FILE is the one place the node calls the tree. The tree itself (the verifier AIR, the leaf and merge proofs,
//! the native root check with its deferred program claims) is lane agg's crate; the node hands it RAW public inputs and
//! every digest stays on that side of the seam, so the circuit's hashing can change without a node change.
//!
//! THE TREE IS lane agg's SSA-row tree (`usdm_agg::tree_ssa`, spec §13): [`prove_leaf`], [`prove_merge`] and
//! [`verify_root`] call it directly. The tree form is the ONE aggregated form (milestone 1's core form and its openings
//! tables were deleted 2026-11-16, when the tree's pins passed on real carriers: a leaf of one payment's three carriers
//! in 2^15 rows proved in 7.7 s, a merge of two leaves in 2^15 proved in 6.9 s, the root checked in 0.19 s, every
//! lying-prover row of the SSA door refused — usdm-agg pins g1 g2 s1 f1 w2 w3 m1 d2 t1 t2, two proving threads). A
//! peer's tree-form body is judged by the real tree, never by a stand-in. The node's own plumbing (carriage,
//! binding, order, the refusal of a root that is not this block's) is pinned against a TEST-ONLY stand-in that says so in
//! its name; that stand-in proves nothing about soundness, which is the tree's own lying-prover pins and the real-node run.
//!
//! §9.6 for the door this serves (`spend_evidence::block_spends_are_evidenced`, tree arm; parallel: a full body's native
//! verify): (1) PoW — the header's, before this; (2) proof — the ONE root proof,
//! here, over every tree-form body's statement in carried order; (3) value — a statement no root proves evidences no
//! ledger row, so its notes and tags are never admitted; (4) replay — the fold's nullifier set, unchanged; (5) bounded —
//! one root of at most [`ROOT_MAX_BYTES`], at most `cover::BLOCK_FIXED_SPEND_TX_COUNT` statements; (6) parity — every
//! field check a full body meets (`spend_evidence::evidence_fields`) runs on a tree-form body too; what differs is only
//! WHO verified the carriers; (7) SAFE AT SCALE — bytes a block: one root + a statement a payment, none of it a function
//! of the bonded set or of height; (8) AI RESISTANT — (a) a proof every node checks. A lying prover gains nothing unless
//! the tree's verifier AIR admits a false statement, which is that crate's row in door-block G4.

use usdm_decider::member_path_gate::MemberTuple;
use usdm_decider::poseidon2_compress::Digest;

/// The four bytes a tree-form body's spend carrier leads with (the rest is its statement's commitment, 32 bytes): one
/// encoding, told apart from a full carrier by its lead.
pub const TREE_TAG: [u8; 4] = *b"AGT1";

/// The merges the canonical tree over `k` payments takes (`usdm_agg::tree_ssa::tree_of`: leaves merged `FAN_IN` at a
/// time, level by level; one payment is its own root). The room rule's arithmetic (`NodeRuntime::agg_room`).
#[must_use]
pub fn merges_for(k: usize) -> usize {
    let (mut n, mut m) = (k, 0usize);
    while n > 1 {
        n = n.div_ceil(usdm_agg::tree_ssa::FAN_IN);
        m += n;
    }
    m
}

/// The most bytes a block's root may be (the proof and its deferred program claims). A bound on what a hostile block can
/// make a peer parse before the proof itself is checked; lane agg's measured root replaces this ceiling with its own.
pub const ROOT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// ⭐ ONE PAYMENT'S STATEMENT — exactly the arguments of today's three carrier checks, nothing else:
/// `usdm_decider::verify_note_spend_bytes(blob, c0, c1, nf, lc, d, t1, fee, hours)`,
/// `member_path_gate::verify_member_path_carrier(carrier, &member)`,
/// `nf_sparse_air::verify_spend_or_decoy_bytes(carrier, &tags)`.
/// A leaf proves "three carriers exist that pass those three checks with these inputs".
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// ⭐ A-F114 (B′): the constant-node form's wrapper statement `[nf tag lanes, binder, lc, end]`; `None`, the member form.
    pub absence: Option<[Digest; 4]>,
}

/// The tree's own statement type (lane agg's crate holds the member tuple as its four digests).
fn tree_statement(st: &PaymentStatement) -> usdm_agg::tree_ssa::PaymentStatement {
    usdm_agg::tree_ssa::PaymentStatement {
        c0: st.c0,
        c1: st.c1,
        nf: st.nf,
        lc: st.lc,
        d: st.d,
        t1: st.t1,
        fee: st.fee,
        hours: st.hours,
        member: [st.member.leaf_commit, st.member.binder, st.member.anchor, st.member.outs],
        tags: st.tags.clone(),
        absence: st.absence,
    }
}

#[cfg(test)]
thread_local! {
    /// ⛔ TEST BUILDS ONLY — the plumbing stand-in is on for this thread (see [`with_plumbing_stand_in`]).
    static STAND_IN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// ⛔ TEST BUILDS ONLY — run `f` with a STAND-IN for the tree that PROVES NOTHING: a "leaf" is a keyed hash of the
/// statement and the carriers' digests, a "root" a keyed hash of its children in order. It lets a pin drive the node's
/// carriage, binding and order rules (a root for other statements, another order, a missing or extra statement, a
/// flipped byte are all refused) before the real tree exists. Soundness is never claimed from it.
#[cfg(test)]
pub fn with_plumbing_stand_in<T>(f: impl FnOnce() -> T) -> T {
    STAND_IN.with(|s| s.set(true));
    let out = f();
    STAND_IN.with(|s| s.set(false));
    out
}

#[cfg(test)]
fn stand_in_on() -> bool {
    STAND_IN.with(std::cell::Cell::get)
}

#[cfg(test)]
fn stand_in_statement(st: &PaymentStatement) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD test-only tree stand-in: a statement (proves nothing)");
    for d in [&st.c0, &st.c1, &st.nf, &st.lc, &st.d, &st.t1] {
        h.update(format!("{d:?}").as_bytes());
    }
    h.update(&st.fee.to_le_bytes());
    h.update(&st.hours.to_le_bytes());
    h.update(format!("{:?}", st.member).as_bytes());
    h.update(&(st.tags.len() as u64).to_le_bytes());
    for t in &st.tags {
        h.update(format!("{t:?}").as_bytes());
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
fn stand_in_root(statements: &[[u8; 32]]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("MUSD test-only tree stand-in: a root (proves nothing)");
    h.update(&(statements.len() as u64).to_le_bytes());
    for s in statements {
        h.update(s);
    }
    // the payments it covers lead, as a real root's `NodeProof::payments` does, so the several-roots door can split
    let mut out = (statements.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(h.finalize().as_bytes());
    out
}

/// HOLDER — prove one payment's leaf: its three carriers verified in circuit against `st` (`usdm_agg::tree_ssa`). `None`
/// when a carrier does not verify.
#[must_use]
pub fn prove_leaf(st: &PaymentStatement, spend: &[u8], member: &[u8], cover: &[u8]) -> Option<Vec<u8>> {
    #[cfg(test)]
    if stand_in_on() {
        if spend.is_empty() || member.is_empty() || cover.is_empty() {
            return None;
        }
        return Some(stand_in_statement(st).to_vec());
    }
    usdm_agg::tree_ssa::prove_leaf(&tree_statement(st), spend, member, cover)
}

/// PRODUCER — merge leaves (each with the one statement it proves) into the block's root, in carried order, along the
/// tree's canonical shape (`usdm_agg::tree_ssa::prove_root`). `None` when a child does not verify.
#[must_use]
pub fn prove_merge(children: &[(PaymentStatement, Vec<u8>)]) -> Option<Vec<u8>> {
    #[cfg(test)]
    if stand_in_on() {
        if children.is_empty() || children.iter().any(|(st, leaf)| leaf.as_slice() != stand_in_statement(st)) {
            return None;
        }
        return Some(stand_in_root(&children.iter().map(|(st, _)| stand_in_statement(st)).collect::<Vec<_>>()));
    }
    let statements: Vec<usdm_agg::tree_ssa::PaymentStatement> = children.iter().map(|(st, _)| tree_statement(st)).collect();
    let leaves: Vec<Vec<u8>> = children.iter().map(|(_, l)| l.clone()).collect();
    usdm_agg::tree_ssa::prove_root(&statements, &leaves)
}

/// ⭐ §14 THE BUNDLE RELAY — how many payments a root covers, read from the root itself (`usdm_agg::tree_ssa::NodeProof::
/// payments`). HOSTILE BYTES: it only tells the door where one root's statements end and the next one's begin;
/// [`verify_root`] then refuses a root whose proof does not cover exactly that many statements (`np.payments` is checked
/// against the slice, and the proof binds the statements' digest), so a lying count refuses the block, never admits.
/// `None` for an empty, oversized or undecodable root, and for a count of zero.
#[must_use]
pub fn root_payments(root: &[u8]) -> Option<usize> {
    if root.is_empty() || root.len() > ROOT_MAX_BYTES {
        return None;
    }
    #[cfg(test)]
    if stand_in_on() {
        let n = u64::from_le_bytes(root.get(..8)?.try_into().ok()?);
        return usize::try_from(n).ok().filter(|n| *n > 0);
    }
    let np: usdm_agg::tree_ssa::NodeProof = postcard::from_bytes(root).ok()?;
    Some(np.payments).filter(|n| *n > 0)
}

/// ⭐ §14 — ANY NODE MERGES: two bundles of the same power-of-two size, each its statements in carried order and its root,
/// into one bundle of twice the size (`usdm_agg::tree_ssa::prove_merge`; a merge of two canonical trees of 2^j is the
/// canonical tree of 2^(j+1), so [`verify_root`] checks the result unchanged). `None` when the sizes differ or are not a
/// power of two, or a child does not verify inside the merge.
/// SAFE AT SCALE: one merge = two children, whatever the bundle size (the tree's fan-in); the caller chooses when.
#[must_use]
pub fn merge_bundles(a: (&[PaymentStatement], &[u8]), b: (&[PaymentStatement], &[u8])) -> Option<Vec<u8>> {
    if a.0.len() != b.0.len() || !a.0.len().is_power_of_two() {
        return None;
    }
    #[cfg(test)]
    if stand_in_on() {
        let (ra, rb) = (stand_in_bundle_root(a.0), stand_in_bundle_root(b.0));
        if a.1 != ra.as_slice() || b.1 != rb.as_slice() {
            return None;
        }
        return Some(stand_in_bundle_root(&[a.0, b.0].concat()));
    }
    let side = |s: &[PaymentStatement]| s.iter().map(tree_statement).collect::<Vec<_>>();
    usdm_agg::tree_ssa::prove_merge(&[(side(a.0), a.1.to_vec()), (side(b.0), b.1.to_vec())])
}

#[cfg(test)]
fn stand_in_bundle_root(statements: &[PaymentStatement]) -> Vec<u8> {
    stand_in_root(&statements.iter().map(stand_in_statement).collect::<Vec<_>>())
}

/// ⭐ §14 — THE BLOCK DOOR FOR SEVERAL ROOTS: the tree-form statements in carried order are split, in the order the roots
/// ride, into consecutive runs of [`root_payments`] each, and every run must be proved by its root. Refused: no root, a
/// root that reads no count, counts that do not sum to exactly the statements (a statement no root covers, or a root
/// reaching past the end), and any run its root does not prove.
/// §9.6 (6) parity: one root is the one-root door exactly. (5) work: one native root check a root (0.19 s MEASURED by
/// lane agg 2026-11-16), at most one root a statement, so bounded by the block's slots.
#[must_use]
pub fn verify_roots(statements: &[PaymentStatement], roots: &[Vec<u8>]) -> bool {
    if statements.is_empty() || roots.is_empty() || roots.len() > statements.len() {
        return false;
    }
    let mut at = 0usize;
    for root in roots {
        let Some(n) = root_payments(root) else { return false };
        let Some(end) = at.checked_add(n).filter(|e| *e <= statements.len()) else { return false };
        if !verify_root(&statements[at..end], root) {
            return false;
        }
        at = end;
    }
    at == statements.len()
}

/// PEER — does `root` prove every statement, in this order? The block door's one question for its tree-form bodies
/// (`usdm_agg::tree_ssa::verify_root`: the statements' digests, every deferred program claim natively, the root proof).
/// Refuses an empty statement list and an oversized root before any of it.
#[must_use]
pub fn verify_root(statements: &[PaymentStatement], root: &[u8]) -> bool {
    if statements.is_empty() || root.is_empty() || root.len() > ROOT_MAX_BYTES {
        return false;
    }
    #[cfg(test)]
    if stand_in_on() {
        return root == stand_in_root(&statements.iter().map(stand_in_statement).collect::<Vec<_>>()).as_slice();
    }
    let sts: Vec<usdm_agg::tree_ssa::PaymentStatement> = statements.iter().map(tree_statement).collect();
    usdm_agg::tree_ssa::verify_root(&sts, root)
}

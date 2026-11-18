# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# CRY-6d step 1: Rust Indexed Merkle Tree nullifier set (logic + selftest), pre-circuit.
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()
if "imt_nullifier_selftest" not in s:
    anc = "pub fn reserve_yield_tree_spend_selftest() -> bool {"
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d: Indexed Merkle Tree (IMT) nullifier set for HIDDEN-nf double-spend prevention. Leaves form
// a value-sorted linked list: leaf = {value, next_index, next_value}. Non-membership of q is witnessed
// by the predecessor "low leaf" L with L.value < q < L.next_value (or L.next_value == 0 for the max).
// A re-spend (same nf) has NO valid low leaf (the gap is occupied by nf itself) -> cannot prove
// non-membership -> rejected. Collision-free (full nf as the sort key) + depth log N. Only the root is
// public, so the spend SET is never enumerable (maximal privacy). This module is the SET LOGIC; the
// in-circuit insert AIR (non-membership + update + append, nf private) is built on top of it next.
const DS_NF_IMT_LEAF: u64 = 0x4e465f494d544c; // "NF_IMTL" domain tag for the IMT leaf commitment

#[derive(Clone)]
pub struct ImtLeaf { pub value: [F; DIGEST], pub next_index: u64, pub next_value: [F; DIGEST] }

fn imt_leaf_hash(l: &ImtLeaf) -> [F; DIGEST] {
    let mut p = Vec::with_capacity(2 + 2 * DIGEST);
    p.push(F::from_u64(DS_NF_IMT_LEAF));
    p.extend_from_slice(&l.value);
    p.push(F::from_u64(l.next_index));
    p.extend_from_slice(&l.next_value);
    run_sponge(&p).digest
}

pub struct ImtSet { pub leaves: Vec<ImtLeaf>, pub depth: usize }

impl ImtSet {
    /// Empty set = one sentinel zero leaf (the smallest possible value) pointing nowhere.
    pub fn new(depth: usize) -> Self {
        ImtSet { leaves: vec![ImtLeaf { value: [F::ZERO; DIGEST], next_index: 0, next_value: [F::ZERO; DIGEST] }], depth }
    }
    fn is_zero(v: &[F; DIGEST]) -> bool { *v == [F::ZERO; DIGEST] }
    /// Total order via canonical bytes (the same canonical encoding the circuit compares limb-wise).
    fn value_lt(a: &[F; DIGEST], b: &[F; DIGEST]) -> bool { publics_to_bytes(a) < publics_to_bytes(b) }
    fn present(&self, q: &[F; DIGEST]) -> bool { self.leaves.iter().any(|l| &l.value == q) }
    /// Index of the predecessor low leaf for q, if q falls in a gap (i.e. is absent).
    fn find_low(&self, q: &[F; DIGEST]) -> Option<usize> {
        for (i, l) in self.leaves.iter().enumerate() {
            if Self::value_lt(&l.value, q) && (Self::is_zero(&l.next_value) || Self::value_lt(q, &l.next_value)) {
                return Some(i);
            }
        }
        None
    }
    /// True iff q is NOT in the set AND a valid low leaf witnesses it (the in-circuit non-membership shape).
    pub fn proves_non_membership(&self, q: &[F; DIGEST]) -> bool {
        !self.present(q) && self.find_low(q).is_some()
    }
    /// Insert q. Returns false on a double-spend (q already present) — the soundness guard.
    pub fn insert(&mut self, q: [F; DIGEST]) -> bool {
        if self.present(&q) { return false; }
        let low = match self.find_low(&q) { Some(i) => i, None => return false };
        let new_idx = self.leaves.len() as u64;
        let q_leaf = ImtLeaf { value: q, next_index: self.leaves[low].next_index, next_value: self.leaves[low].next_value };
        self.leaves[low].next_index = new_idx;
        self.leaves[low].next_value = q;
        self.leaves.push(q_leaf);
        true
    }
    pub fn root(&self) -> [F; DIGEST] {
        let hs: Vec<[F; DIGEST]> = self.leaves.iter().map(imt_leaf_hash).collect();
        ry_build_tree(&hs, self.depth).0
    }
}

/// CRY-6d gate: the IMT nullifier set has correct sorted-set + double-spend semantics — root advances on
/// insert, non-membership holds for absent values + fails for present ones, and a re-spend is rejected.
pub fn imt_nullifier_selftest() -> bool {
    let nf = |x: u64| -> [F; DIGEST] { let mut a = [F::ZERO; DIGEST]; a[0] = F::from_u64(x); a };
    let mut t = ImtSet::new(8);
    let r0 = t.root();
    if !t.proves_non_membership(&nf(50)) { return false; }       // empty set: everything absent
    if !t.insert(nf(50)) || !t.insert(nf(30)) || !t.insert(nf(70)) { return false; }
    if t.root() == r0 { return false; }                          // root advanced
    if !t.proves_non_membership(&nf(40)) { return false; }       // absent (gap 30<40<50) -> non-member
    if t.proves_non_membership(&nf(50)) { return false; }        // present -> NOT non-member
    if t.insert(nf(50)) { return false; }                        // re-spend rejected (double-spend guard)
    if !t.insert(nf(40)) { return false; }                       // a genuinely-new nf still inserts
    true
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("circuit IMT added")
else: print("circuit IMT present; skip")

# FFI selftest export.
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_imt_nullifier_selftest" not in fs:
    io = "    ry_note_tree_root_bytes, ry_note_tree_path_bytes, reserve_yield_tree_spend_selftest,"
    inew = io + "\n    imt_nullifier_selftest,"
    if fs.count(io) != 1: print("FATAL import anchor x%d" % fs.count(io)); sys.exit(1)
    fs = fs.replace(io, inew, 1)
    anc2 = "#[no_mangle]\npub extern \"C\" fn pqpool_reserve_yield_tree_spend_selftest() -> i32 {"
    fn2 = '''#[no_mangle]
pub extern "C" fn pqpool_imt_nullifier_selftest() -> i32 {
    if imt_nullifier_selftest() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_tree_spend_selftest() -> i32 {'''
    if fs.count(anc2) != 1: print("FATAL externc anchor x%d" % fs.count(anc2)); sys.exit(1)
    fs = fs.replace(anc2, fn2, 1); open(f, "w").write(fs); print("ffi IMT added")
else: print("ffi IMT present; skip")

h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_imt_nullifier_selftest" not in hs:
    ha = "int32_t pqpool_reserve_yield_tree_spend_selftest(void);"
    hn = "int32_t pqpool_imt_nullifier_selftest(void);\n" + ha
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    open(h, "w").write(hs.replace(ha, hn, 1)); print("ffi.h IMT added")
else: print("ffi.h IMT present; skip")
print("DONE")
